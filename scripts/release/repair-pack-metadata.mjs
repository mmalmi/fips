// Adapted from qualified canonical @hashtree/core 0.3.2 metadata round-trip method.
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const task=process.argv[2],rootHash=process.argv[3],rootKey=process.argv[4];
const base=path.join(task,'sdk/node_modules/@hashtree/core/dist');
const {decodeTreeNode,encodeTreeNode}=await import(pathToFileURL(path.join(base,'codec.js')));
const {decryptChk,encryptChk}=await import(pathToFileURL(path.join(base,'crypto.js')));
const hex=b=>Buffer.from(b).toString('hex');
const hash=b=>createHash('sha256').update(b).digest('hex');
const checks=[];
async function load(h,k){
 let bytes,last;
 for(const host of ['https://cdn.iris.to','https://upload.iris.to']){
  try{const r=await fetch(host+'/'+h,{signal:AbortSignal.timeout(30000)});if(!r.ok)throw new Error('HTTP '+r.status);bytes=new Uint8Array(await r.arrayBuffer());if(hash(bytes)!==h)throw new Error('ciphertext hash mismatch');break;}catch(e){last=e;bytes=undefined;}
 }
 if(!bytes)throw last;
 const plain=await decryptChk(bytes,new Uint8Array(Buffer.from(k,'hex')));
 const node=decodeTreeNode(plain),encoded=encodeTreeNode(node);
 if(!Buffer.from(encoded).equals(Buffer.from(plain)))throw new Error('SDK encode round trip differs');
 const round=await encryptChk(encoded);
 if(hash(round.ciphertext)!==h || hex(round.key)!==k || !Buffer.from(round.ciphertext).equals(Buffer.from(bytes)))throw new Error('CHK round trip differs');
 checks.push({hash:h,plainBytes:plain.length,cipherBytes:bytes.length,roundTripByteIdentical:true});
 return node;
}
const names=['.git','objects','pack'];const levels=[];
let h=rootHash,k=rootKey;
for(let i=0;i<=names.length;i++){
 const node=await load(h,k);if(node.type!==2)throw new Error('expected directory');levels.push({node,oldHash:h,oldKey:k});
 if(i<names.length){const child=node.links.find(x=>x.name===names[i]);if(!child)throw new Error('missing metadata path');h=hex(child.hash);k=hex(child.key);}
}
const leaf=levels.at(-1).node;const before=encodeTreeNode(leaf);const changes=[];const untouched=[];
for(const entry of leaf.links){
 if(!/^(pack-[0-9a-f]{40})\.(pack|idx)$/.test(entry.name)){untouched.push({name:entry.name,size:entry.size,ciphertextCid:hex(entry.hash)});continue;}
 if(entry.size!==0)throw new Error('expected observed zero size');
 const file=path.join(task,'source-tree/.git/objects/pack',entry.name);const stat=await fs.stat(file);if(!stat.isFile()||stat.size<=0)throw new Error('invalid pack file');
 changes.push({name:entry.name,oldSize:entry.size,newSize:stat.size,ciphertextCid:hex(entry.hash),fileType:entry.type});entry.size=stat.size;
}
const measured=(await fs.readdir(path.join(task,'source-tree/.git/objects/pack'))).filter(name=>/^(pack-[0-9a-f]{40})\.(pack|idx)$/.test(name));
if(changes.length===0||changes.length!==measured.length||!measured.every(name=>changes.some(x=>x.name===name)))throw new Error('pack/index metadata set differs');
// The complete file bytes already passed immutable Git verification. Only s changes here.
const restored=decodeTreeNode(encodeTreeNode(leaf));for(const x of restored.links){const change=changes.find(c=>c.name===x.name);if(change)x.size=change.oldSize;}
if(!Buffer.from(encodeTreeNode(restored)).equals(Buffer.from(before)))throw new Error('unexpected leaf metadata delta');
const nodes=[];await fs.mkdir(path.join(task,'corrected-nodes'));
let child;
for(let i=levels.length-1;i>=0;i--){
 const level=levels[i];
 if(child){const prior=encodeTreeNode(level.node);const entry=level.node.links.find(x=>x.name===names[i]);const oldHash=entry.hash,oldKey=entry.key;entry.hash=new Uint8Array(Buffer.from(child.hash,'hex'));entry.key=new Uint8Array(Buffer.from(child.key,'hex'));const restoredParent=decodeTreeNode(encodeTreeNode(level.node));const same=restoredParent.links.find(x=>x.name===names[i]);same.hash=oldHash;same.key=oldKey;if(!Buffer.from(encodeTreeNode(restoredParent)).equals(Buffer.from(prior)))throw new Error('unexpected ancestor delta');}
 const plain=encodeTreeNode(level.node),cipher=await encryptChk(plain),newHash=hash(cipher.ciphertext),newKey=hex(cipher.key);
 if(newHash===level.oldHash)throw new Error('expected corrected metadata hash');const file=path.join(task,'corrected-nodes',newHash+'.bin');await fs.writeFile(file,cipher.ciphertext,{mode:0o600});
 nodes.push({path:i===0?'/':'/'+names.slice(0,i).join('/'),oldHash:level.oldHash,newHash,newKey,bytes:cipher.ciphertext.length,file});child={hash:newHash,key:newKey};
}
if(nodes.length!==4)throw new Error('wrong directory mutation count');
const result={oldRootHash:rootHash,newRootHash:child.hash,newRootKey:child.key,changedDirectoryNodes:4,changedSizeFields:changes.length,allObjectCiphertextCidsPreserved:true,allRefsAndHeadBytesPreserved:true,oldRoundTrips:checks,sizeChanges:changes,untouchedPackDirectoryEntries:untouched,nodes};
await fs.writeFile(path.join(task,'metadata-plan.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({newRootHash:result.newRootHash,changedDirectoryNodes:4,changedSizeFields:changes.length,oldRoundTrips:checks.length}));
