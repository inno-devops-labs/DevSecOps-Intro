import pathlib,subprocess,json
L=pathlib.Path('/var/tmp/lab12-alexbittit');out={}
base=['ctr','--address',str(L/'containerd.sock'),'--namespace','lab12']
command=['sh','-c','echo "OVERWRITTEN" > /host_tmp/lab12-target; printf "devices="; ls /dev | wc -l; grep ^CapEff /proc/1/status; uname -r']
for rt in ['runc','kata']:
 target=pathlib.Path('/tmp/lab12-target');assert not target.exists()
 target.write_text('original\n')
 args=base+['run','--rm','--privileged','--privileged-without-host-devices','--mount','type=bind,src=/tmp,dst=/host_tmp,options=rbind:rw']
 if rt=='kata':args+=['--runtime','io.containerd.kata.v2']
 args+=['docker.io/library/alpine:3.20','lab12-bonus-controlled']+command
 print('$ '+subprocess.list2cmdline(args),flush=True)
 try:
  p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  out[rt]={'command':args,'before':'original','exit_code':p.returncode,'output':p.stdout.strip(),'after':target.read_text().strip()}
  print(p.stdout,flush=True); print('HOST FILE:',out[rt]['after'],flush=True)
 finally:target.unlink(missing_ok=True)
 (L/'results/controlled-privileged.json').write_text(json.dumps(out,indent=2))
