import subprocess,json,pathlib,time,statistics,os
LAB=pathlib.Path('/var/tmp/lab12-alexbittit'); OUT=LAB/'results';OUT.mkdir(exist_ok=True)
BASE=[str(LAB/'bin/nerdctl'),'--address',str(LAB/'containerd.sock'),'--namespace','lab12','--data-root',str(LAB/'nerdctl-data'),'--cgroup-manager','cgroupfs']
IMAGE='alpine:3.20'
results={'image':IMAGE,'runtimes':{},'date_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
def run(args,check=True):
 print('$ '+' '.join(args),flush=True)
 p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 print(p.stdout,end='' if p.stdout.endswith('\n') else '\n',flush=True)
 if check and p.returncode:raise RuntimeError(f'Command failed: {p.returncode}')
 return {'exit_code':p.returncode,'output':p.stdout.strip()}
def n(args,check=True):return run(BASE+args,check)
def container(rt,cmd,privileged=False,extra=None,check=True):
 args=['run','--rm','--net=none']
 if rt=='kata':args+=['--runtime=io.containerd.kata.v2']
 if privileged:args+=['--privileged']
 if extra:args+=extra
 return n(args+[IMAGE]+cmd,check)
def save(): (OUT/'measurements.json').write_text(json.dumps(results,indent=2))
results['host_kernel']=run(['uname','-r'])['output']
results['image_inspect']=n(['image','inspect',IMAGE])['output']
results['kata_version']=pathlib.Path('/opt/kata/VERSION').read_text().strip()
for rt in ['runc','kata']:
 d=results['runtimes'][rt]={}
 for label,cmd in [('kernel',['uname','-r']),('devices',['sh','-c','ls /dev | wc -l']),('capabilities',['sh','-c','grep ^CapEff /proc/1/status'])]:
  d[label]=container(rt,cmd)
 save()
for rt in ['runc','kata']:
 d=results['runtimes'][rt]
 container(rt,['true'])
 d['startup_seconds']=[]
 for i in range(5):
  args=['run','--rm','--net=none']+(['--runtime=io.containerd.kata.v2'] if rt=='kata' else [])+[IMAGE,'true']
  timed=run([str(LAB/'time/usr/bin/time'),'-f','LAB12_SECONDS=%e']+BASE+args)
  elapsed=float(next(x.split('=',1)[1] for x in timed['output'].splitlines() if x.startswith('LAB12_SECONDS=')))
  d['startup_seconds'].append(elapsed)
 d['startup_median_seconds']=statistics.median(d['startup_seconds'])
 d['io']=container(rt,['sh','-c','dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1'])
 save()
for rt in ['runc','kata']:
 d=results['runtimes'][rt]
 assert not pathlib.Path('/tmp/lab12-target').exists(), 'Existing host target would be overwritten'
 try:
  pathlib.Path('/tmp/lab12-target').write_text('original\n')
  d['bonus_before']=pathlib.Path('/tmp/lab12-target').read_text().strip()
  d['bonus_write']=container(rt,['sh','-c','echo "OVERWRITTEN" > /host_tmp/lab12-target'],True,['-v','/tmp:/host_tmp'],False)
  d['bonus_after']=pathlib.Path('/tmp/lab12-target').read_text().strip()
  print(f'HOST FILE AFTER {rt}: {d["bonus_after"]}',flush=True)
 finally:pathlib.Path('/tmp/lab12-target').unlink(missing_ok=True)
 d['privileged_devices']=container(rt,['sh','-c','ls /dev | wc -l'],True,check=False)
 d['privileged_capabilities']=container(rt,['sh','-c','grep ^CapEff /proc/1/status'],True,check=False)
 save()
print('MEASUREMENTS COMPLETE',flush=True)
