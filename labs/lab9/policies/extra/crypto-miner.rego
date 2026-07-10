package k8s.security.extra

miner_indicators := [
  "xmrig",
  "cpuminer",
  "cgminer",
  "minerd",
  "monero",
  "stratum+tcp",
  "--donate-level",
  "pool.minexmr.com",
]

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  cmd := array.concat(c.command, c.args)
  arg := cmd[_]
  ind := miner_indicators[_]
  contains(lower(arg), lower(ind))
  msg := sprintf("container %q command/args contain crypto-miner indicator %q", [c.name, ind])
}

deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  ind := miner_indicators[_]
  contains(lower(c.image), lower(ind))
  msg := sprintf("container %q image %q contains crypto-miner indicator %q", [c.name, c.image, ind])
}
