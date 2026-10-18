import pathlib, subprocess, tempfile, tomllib
script=pathlib.Path(__file__).with_name('configure-containerd-kata.sh')
for plugin in ['io.containerd.cri.v1.runtime','io.containerd.grpc.v1.cri']:
 with tempfile.TemporaryDirectory() as d:
  conf=pathlib.Path(d)/'config.toml'
  conf.write_text(f"version = 3\n[plugins.'{plugin}']\n[plugins.'{plugin}'.containerd.runtimes.runc]\n  runtime_type = 'io.containerd.runc.v2'\n")
  for _ in range(2):subprocess.run(['bash',str(script),str(conf)],check=True,capture_output=True)
  x=tomllib.loads(conf.read_text())
  assert x['plugins'][plugin]['containerd']['runtimes']['kata']['runtime_type']=='io.containerd.kata.v2'
  assert conf.read_text().count("runtime_type = 'io.containerd.kata.v2'")==1
  assert x['plugins'][plugin]['containerd']['runtimes']['runc']['runtime_type']=='io.containerd.runc.v2'
print('PASS: v2/v3 containerd runtime registration is idempotent and preserves runc')
