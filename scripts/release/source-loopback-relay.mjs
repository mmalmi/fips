import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const task=process.argv[2];const {WebSocketServer}=await import(pathToFileURL(path.join(task,'sdk/node_modules/ws/wrapper.mjs')));
const events=new Map(),subs=new Map();
function matches(e,f){
 if(f.ids&&!f.ids.some(x=>e.id.startsWith(x)))return false;
 if(f.authors&&!f.authors.some(x=>e.pubkey.startsWith(x)))return false;
 if(f.kinds&&!f.kinds.includes(e.kind))return false;
 if(f.since&&e.created_at<f.since)return false;if(f.until&&e.created_at>f.until)return false;
 for(const [key,values] of Object.entries(f))if(key.startsWith('#')&&!e.tags.some(t=>t[0]===key.slice(1)&&values.includes(t[1])))return false;
 return true;
}
const wss=new WebSocketServer({host:'127.0.0.1',port:0,maxPayload:1024*1024});
wss.on('connection',ws=>{subs.set(ws,new Map());ws.on('message',bytes=>{
 try{const m=JSON.parse(bytes.toString());
  if(m[0]==='EVENT'){
   const e=m[1];if(!e||!e.id||!e.pubkey||!e.sig||!Array.isArray(e.tags)||events.size>=10)throw new Error('invalid fixture event');events.set(e.id,e);ws.send(JSON.stringify(['OK',e.id,true,'']));
   for(const [peer,ss] of subs)for(const [id,filters] of ss)if(filters.some(f=>matches(e,f)))peer.send(JSON.stringify(['EVENT',id,e]));
  }else if(m[0]==='REQ'){
   const [_,id,...filters]=m;subs.get(ws).set(id,filters);
   for(const e of [...events.values()].sort((a,b)=>b.created_at-a.created_at))if(filters.some(f=>matches(e,f)))ws.send(JSON.stringify(['EVENT',id,e]));ws.send(JSON.stringify(['EOSE',id]));
  }else if(m[0]==='CLOSE')subs.get(ws).delete(m[1]);
 }catch(e){ws.send(JSON.stringify(['NOTICE','fixture rejected malformed request']));}
 });ws.on('close',()=>subs.delete(ws));});
await new Promise((resolve,reject)=>{wss.once('listening',resolve);wss.once('error',reject);});
const address=wss.address();await fs.writeFile(path.join(task,'fixture-address.json'),JSON.stringify({host:address.address,port:address.port,url:'ws://127.0.0.1:'+address.port})+'\n',{mode:0o600});
console.log('Loopback fixture ready');
function stop(){for(const ws of wss.clients)ws.close();wss.close(()=>process.exit(0));setTimeout(()=>process.exit(0),1000).unref();}
process.on('SIGTERM',stop);process.on('SIGINT',stop);
