"""Supplicant/kernel command shims for the existing real Linux guard fixture."""

UBUS = r'''import json,os,sys
from pathlib import Path
p=Path(os.environ['MESH_STATE']);s=json.loads(p.read_text())
command=json.loads(sys.argv[-1])['command'];parts=command.split()
with open(os.environ['MESH_LOG'],'a') as f:f.write(command+'\n')
if command==os.environ.get('OPEN_FAIL_BEFORE'):sys.exit(1)
result='FAIL';networks=s['networks'];current=s['current']
if command=='LIST_NETWORKS':
 result='network id / ssid / bssid / flags\n'+'\n'.join(
  f'{key}\tmesh\tany\t'+('[CURRENT]' if current==int(key) else '[DISABLED]')
  for key in networks)
elif parts[0]=='GET_NETWORK' and parts[1] in networks:
 value=networks[parts[1]].get(parts[2],'FAIL');result=str(value)
elif parts[0]=='GET':result=str(s['globals'].get(parts[1],'FAIL'))
elif parts[0]=='SET':s['globals'][parts[1]]=int(parts[2]);result='OK'
elif command=='ADD_NETWORK':
 key=str(max(int(n) for n in networks)+1);networks[key]={};result=key
elif parts[0]=='SET_NETWORK' and parts[1] in networks:
 value=parts[3]
 if parts[2] in ('ssid','id_str'):value='"'+bytes.fromhex(value).decode()+'"'
 networks[parts[1]][parts[2]]=value;result='OK'
elif command=='STATUS':
 result='wpa_state='+('COMPLETED' if current is not None else 'DISCONNECTED')
 if current is not None:result+='\nid='+str(current)+'\nfreq='+str(networks[str(current)]['frequency'])
elif command=='MESH_GROUP_REMOVE mesh0':s['current']=None;result='OK'
elif parts[0]=='MESH_GROUP_ADD' and parts[1] in networks:
 s['current']=int(parts[1]);result='OK'
 # Model netifd reapplying its original kernel mesh parameters at COMPLETED.
 s['kernel']={'mesh_max_peer_links':32,'mesh_plink_timeout':1800,'mesh_fwding':0}
elif parts[0]=='REMOVE_NETWORK' and parts[1] in networks:
 del networks[parts[1]];result='OK'
carrier=s['current'] is not None and not os.environ.get('MESH_NO_CARRIER')
Path(os.environ['MESH_NET'],'carrier').write_text('1' if carrier else '0')
p.write_text(json.dumps(s))
if command==os.environ.get('OPEN_LOST_REPLY'):sys.exit(1)
print(json.dumps({'result':result}))
'''

IW = r'''import json,os,sys
from pathlib import Path
p=Path(os.environ['MESH_STATE']);s=json.loads(p.read_text());a=sys.argv[1:]
if a[2:4]==['get','mesh_param']:
 values=s['kernel'] if s['current'] is not None else {
  'mesh_max_peer_links':32,'mesh_plink_timeout':1800,'mesh_fwding':1}
 print(str(values[a[4]])+(' seconds' if a[4]=='mesh_plink_timeout' else ''))
elif a[2:4]==['set','mesh_param']:
 if s['current'] is None:sys.exit(1)
 s['kernel'][a[4]]=int(a[5]);p.write_text(json.dumps(s))
else:sys.exit(2)
'''

IP = r'''import os
if os.environ.get('MESH_IP'):print('1: mesh0 inet6 fe80::1/64 scope link')
'''
