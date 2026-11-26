import subprocess,pathlib,time,json,statistics
LAB=pathlib.Path('/var/tmp/lab12-alexbittit'); OUT=LAB/'results'
BASE=[str(LAB/'bin/nerdctl'),'--address',str(LAB/'containerd.sock'),'--namespace','lab12','--data-root',str(LAB/'nerdctl-data'),'--cgroup-manager','cgroupfs']
def n(args):
 p=subprocess.run(BASE+args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
 return p.stdout.strip()
def processes():
 rows={}
 for p in pathlib.Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace').strip()
   status=(p/'status').read_text();ppid=int(next(x.split()[1] for x in status.splitlines() if x.startswith('PPid:')))
   rows[int(p.name)]={'pid':int(p.name),'ppid':ppid,'command':cmd}
  except (FileNotFoundError,ProcessLookupError,PermissionError):continue
 return rows
def sample(cid):
 rows=processes()
 roots=[pid for pid,r in rows.items() if 'containerd-shim' in r['command'].split(' ')[0] and cid in r['command']]
 assert len(roots)==1,(cid,roots)
 selected=set(roots)
 while True:
  new={pid for pid,r in rows.items() if r['ppid'] in selected}
  if new<=selected:break
  selected|=new
 out=[]
 for pid in sorted(selected):
  r=rows[pid]
  text=pathlib.Path(f'/proc/{pid}/smaps_rollup').read_text()
  r['pss_kib']=int(next(x.split()[1] for x in text.splitlines() if x.startswith('Pss:')))
  r['rss_kib']=int(next(x.split()[1] for x in text.splitlines() if x.startswith('Rss:')))
  out.append(r)
 return {'total_pss_kib':sum(r['pss_kib'] for r in out),'processes':out}
result={}
for rt in ['runc','kata']:
 args=['run','-d','--name','lab12-memory-'+rt,'--net=none']
 if rt=='kata':args+=['--runtime=io.containerd.kata.v2']
 cid=n(args+['alpine:3.20','sleep','180']).splitlines()[-1]
 print('Started',rt,cid,flush=True)
 try:
  time.sleep(5)
  samples=[]
  for i in range(5):
   s=sample(cid); samples.append(s);print(rt,'sample',i+1,'PSS KiB',s['total_pss_kib'],flush=True);time.sleep(1)
  result[rt]={'container_id':cid,'settle_seconds':5,'sample_interval_seconds':1,'samples':samples,'median_pss_kib':statistics.median(s['total_pss_kib'] for s in samples)}
 finally:print(n(['rm','-f',cid]),flush=True)
 (OUT/'memory.json').write_text(json.dumps(result,indent=2))
print(json.dumps({rt:result[rt]['median_pss_kib'] for rt in result}),flush=True)
