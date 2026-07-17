# Lab 12 — BONUS — Submission

## Task 1: Install + Hello-World

### Host environment
- Kernel (host): `Linux HaroldP 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2 x86_64 x86_64 x86_64 GNU/Linux`
- KVM accessible: `crw-rw----+ 1 root kvm 10, 232 Jul 17 22:24 /dev/kvm`
- containerd version: `containerd github.com/containerd/containerd/v2 v2.3.2 fff62f14765df376e5fc36f5a8f8e795b5670f61`

### Kata installation
- Kata version: `3.32.0`
- containerd config snippet:
```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
```

### Kernel inside containers
**runc:**
```
Linux HaroldP 6.17.0-40-generic #40~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Tue Jun 23 16:48:12 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

**kata:**
```
Linux d1e37c5c0354 6.18.35 #1 SMP Mon Jun 15 12:55:58 UTC 2026 x86_64 Linux
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 23

```

### Why the kernel differs (Reading 12)
Reading 12 explains the model. Reference Lecture 7 slide 14 — runc CVE-2024-21626 ("Leaky Vessels").
What does the kernel difference imply for that attack class? (2-3 sentences.)

This difference implies that for Leaky vessels, escape in Kata compromises VMs guest kernel but not the host. In runc, however, escape grants access to host. So kata's isolation of hardware contains the blast radius to the isolated VM.

## Task 2: Isolation + Performance

### Isolation: /dev diff
```
2,257c2,17
< drwxr-xr-x  20 root   root            5120 Jul 17 22:24 .
< drwxr-xr-x  24 root   root            4096 Jun 15 15:48 ..
< crw-r--r--   1 root   root       10,   235 Jul 17 19:00 autofs
< drwxr-xr-x   2 root   root            1000 Jul 17 19:05 block
< crw-------   1 root   root       10,   234 Jul 17 19:00 btrfs-control
< drwxr-xr-x   3 root   root              60 Jul 17 19:00 bus
< drwxr-xr-x   2 root   root            4500 Jul 17 23:00 char
< crw--w----   1 root   tty         5,     1 Jul 17 19:00 console
< lrwxrwxrwx   1 root   root              11 Jul 17 19:00 core -> /proc/kcore
< drwxr-xr-x  14 root   root             280 Jul 17 19:00 cpu
< crw-------   1 root   root       10,   260 Jul 17 19:00 cpu_dma_latency
< crw-------   1 root   root       10,   203 Jul 17 19:00 cuse
< drwxr-xr-x  10 root   root             200 Jul 17 19:00 disk
< drwxr-xr-x   2 root   root              60 Jul 17 19:00 dma_heap
< drwxr-xr-x   3 root   root             100 Jul 17 19:00 dri
< crw-------   1 root   root      235,     0 Jul 17 19:00 drm_dp_aux0
< crw-------   1 root   root       10,   258 Jul 17 19:00 ecryptfs
< crw-rw----   1 root   video      29,     0 Jul 17 19:00 fb0
< lrwxrwxrwx   1 root   root              13 Jul 17 19:00 fd -> /proc/self/fd
< crw-rw-rw-   1 root   root        1,     7 Jul 17 19:00 full
< crw-rw-rw-   1 root   root       10,   229 Jul 17 19:00 fuse
< crw-------   1 root   root      254,     0 Jul 17 19:00 gpiochip0
< crw-------   1 root   root      240,     0 Jul 17 19:00 hidraw0
< crw-------   1 root   root       10,   228 Jul 17 19:00 hpet
< drwxr-xr-x   2 root   root               0 Jul 17 19:00 hugepages
< crw-------   1 root   root       10,   183 Jul 17 19:00 hwrng
< crw-------   1 root   root       89,     0 Jul 17 19:00 i2c-0
< crw-------   1 root   root       89,     1 Jul 17 19:00 i2c-1
< crw-------   1 root   root       89,     2 Jul 17 19:00 i2c-2
< crw-------   1 root   root       89,     3 Jul 17 19:00 i2c-3
< crw-------   1 root   root       89,     4 Jul 17 19:00 i2c-4
< crw-------   1 root   root       89,     5 Jul 17 19:00 i2c-5
< crw-------   1 root   root       89,     6 Jul 17 19:00 i2c-6
< crw-------   1 root   root       89,     7 Jul 17 19:00 i2c-7
< lrwxrwxrwx   1 root   root              12 Jul 17 19:00 initctl -> /run/initctl
< drwxr-xr-x   3 root   root             400 Jul 17 23:00 input
< crw-rw----   1 root   render    511,     0 Jul 17 19:00 kfd
< crw-r--r--   1 root   root        1,    11 Jul 17 19:00 kmsg
< crw-rw----+  1 root   kvm        10,   232 Jul 17 22:24 kvm
< lrwxrwxrwx   1 root   root              28 Jul 17 19:00 log -> /run/systemd/journal/dev-log
< brw-rw----   1 root   disk        7,     0 Jul 17 19:00 loop0
< brw-rw----   1 root   disk        7,     1 Jul 17 19:00 loop1
< brw-rw----   1 root   disk        7,    10 Jul 17 19:00 loop10
< brw-rw----   1 root   disk        7,    11 Jul 17 19:00 loop11
< brw-rw----   1 root   disk        7,    12 Jul 17 19:05 loop12
< brw-rw----   1 root   disk        7,    13 Jul 17 19:00 loop13
< brw-rw----   1 root   disk        7,    14 Jul 17 19:00 loop14
< brw-rw----   1 root   disk        7,    15 Jul 17 19:00 loop15
< brw-rw----   1 root   disk        7,    16 Jul 17 19:00 loop16
< brw-rw----   1 root   disk        7,    17 Jul 17 19:00 loop17
< brw-rw----   1 root   disk        7,    18 Jul 17 19:00 loop18
< brw-rw----   1 root   disk        7,    19 Jul 17 19:00 loop19
< brw-rw----   1 root   disk        7,     2 Jul 17 19:00 loop2
< brw-rw----   1 root   disk        7,    20 Jul 17 19:00 loop20
< brw-rw----   1 root   disk        7,    21 Jul 17 19:00 loop21
< brw-rw----   1 root   disk        7,    22 Jul 17 19:00 loop22
< brw-rw----   1 root   disk        7,    23 Jul 17 19:00 loop23
< brw-rw----   1 root   disk        7,    24 Jul 17 19:00 loop24
< brw-rw----   1 root   disk        7,    25 Jul 17 19:00 loop25
< brw-rw----   1 root   disk        7,    26 Jul 17 19:00 loop26
< brw-rw----   1 root   disk        7,    27 Jul 17 19:00 loop27
< brw-rw----   1 root   disk        7,    28 Jul 17 19:00 loop28
< brw-rw----   1 root   disk        7,    29 Jul 17 19:00 loop29
< brw-rw----   1 root   disk        7,     3 Jul 17 19:00 loop3
< brw-rw----   1 root   disk        7,    30 Jul 17 19:00 loop30
< brw-rw----   1 root   disk        7,    31 Jul 17 19:00 loop31
< brw-rw----   1 root   disk        7,    32 Jul 17 19:00 loop32
< brw-rw----   1 root   disk        7,    33 Jul 17 19:00 loop33
< brw-rw----   1 root   disk        7,    34 Jul 17 19:00 loop34
< brw-rw----   1 root   disk        7,    35 Jul 17 19:00 loop35
< brw-rw----   1 root   disk        7,    36 Jul 17 19:00 loop36
< brw-rw----   1 root   disk        7,    37 Jul 17 19:00 loop37
< brw-rw----   1 root   disk        7,    38 Jul 17 19:00 loop38
< brw-rw----   1 root   disk        7,    39 Jul 17 19:00 loop39
< brw-rw----   1 root   disk        7,     4 Jul 17 19:00 loop4
< brw-rw----   1 root   disk        7,    40 Jul 17 19:00 loop40
< brw-rw----   1 root   disk        7,    41 Jul 17 19:00 loop41
< brw-rw----   1 root   disk        7,    42 Jul 17 19:05 loop42
< brw-rw----   1 root   disk        7,     5 Jul 17 19:00 loop5
< brw-rw----   1 root   disk        7,     6 Jul 17 19:00 loop6
< brw-rw----   1 root   disk        7,     7 Jul 17 19:00 loop7
< brw-rw----   1 root   disk        7,     8 Jul 17 19:00 loop8
< brw-rw----   1 root   disk        7,     9 Jul 17 19:00 loop9
< crw-rw----   1 root   disk       10,   237 Jul 17 19:00 loop-control
< drwxr-xr-x   2 root   root              60 Jul 17 19:00 mapper
< crw-------   1 root   root       10,   227 Jul 17 19:00 mcelog
< crw-rw----+  1 root   video     234,     0 Jul 17 19:00 media0
< crw-r-----   1 root   kmem        1,     1 Jul 17 19:00 mem
< drwxrwxrwt   2 root   root              40 Jul 17 19:00 mqueue
< drwxr-xr-x   2 root   root              60 Jul 17 19:00 net
< crw-------   1 root   root      238,     0 Jul 17 19:00 ng0n1
< crw-rw-rw-   1 root   root        1,     3 Jul 17 19:00 null
< crw-------   1 root   root      239,     0 Jul 17 19:00 nvme0
< brw-rw----   1 root   disk      259,     0 Jul 17 19:00 nvme0n1
< brw-rw----   1 root   disk      259,     1 Jul 17 19:00 nvme0n1p1
< brw-rw----   1 root   disk      259,     2 Jul 17 19:00 nvme0n1p2
< brw-rw----   1 root   disk      259,     3 Jul 17 19:00 nvme0n1p3
< brw-rw----   1 root   disk      259,     4 Jul 17 19:00 nvme0n1p4
< crw-------   1 root   root       10,   144 Jul 17 19:00 nvram
< crw-r-----   1 root   kmem        1,     4 Jul 17 19:00 port
< crw-------   1 root   root      108,     0 Jul 17 19:00 ppp
< crw-------   1 root   root       10,     1 Jul 17 19:00 psaux
< crw-rw-rw-   1 root   tty         5,     2 Jul 17 23:07 ptmx
< drwxr-xr-x   2 root   root               0 Jul 17 19:00 pts
< crw-rw-rw-   1 root   root        1,     8 Jul 17 19:00 random
< crw-rw-r--+  1 root   root       10,   242 Jul 17 19:00 rfkill
< lrwxrwxrwx   1 root   root               4 Jul 17 19:00 rtc -> rtc0
< crw-------   1 root   root      247,     0 Jul 17 19:00 rtc0
< drwxrwxrwt   2 root   root             100 Jul 17 22:24 shm
< crw-------   1 root   root       10,   231 Jul 17 19:00 snapshot
< drwxr-xr-x   3 root   root             240 Jul 17 19:00 snd
< lrwxrwxrwx   1 root   root              15 Jul 17 19:00 stderr -> /proc/self/fd/2
< lrwxrwxrwx   1 root   root              15 Jul 17 19:00 stdin -> /proc/self/fd/0
< lrwxrwxrwx   1 root   root              15 Jul 17 19:00 stdout -> /proc/self/fd/1
< crw-rw----   1 tss    root       10,   224 Jul 17 19:00 tpm0
< crw-rw----   1 tss    tss       252, 65536 Jul 17 19:00 tpmrm0
< crw-rw-rw-   1 root   tty         5,     0 Jul 17 23:07 tty
< crw--w----   1 root   tty         4,     0 Jul 17 19:00 tty0
< crw--w----   1 root   tty         4,     1 Jul 17 19:00 tty1
< crw--w----   1 root   tty         4,    10 Jul 17 19:00 tty10
< crw--w----   1 root   tty         4,    11 Jul 17 19:00 tty11
< crw--w----   1 root   tty         4,    12 Jul 17 19:00 tty12
< crw--w----   1 root   tty         4,    13 Jul 17 19:00 tty13
< crw--w----   1 root   tty         4,    14 Jul 17 19:00 tty14
< crw--w----   1 root   tty         4,    15 Jul 17 19:00 tty15
< crw--w----   1 root   tty         4,    16 Jul 17 19:00 tty16
< crw--w----   1 root   tty         4,    17 Jul 17 19:00 tty17
< crw--w----   1 root   tty         4,    18 Jul 17 19:00 tty18
< crw--w----   1 root   tty         4,    19 Jul 17 19:00 tty19
< crw--w----   1 polina tty         4,     2 Jul 17 19:00 tty2
< crw--w----   1 root   tty         4,    20 Jul 17 19:00 tty20
< crw--w----   1 root   tty         4,    21 Jul 17 19:00 tty21
< crw--w----   1 root   tty         4,    22 Jul 17 19:00 tty22
< crw--w----   1 root   tty         4,    23 Jul 17 19:00 tty23
< crw--w----   1 root   tty         4,    24 Jul 17 19:00 tty24
< crw--w----   1 root   tty         4,    25 Jul 17 19:00 tty25
< crw--w----   1 root   tty         4,    26 Jul 17 19:00 tty26
< crw--w----   1 root   tty         4,    27 Jul 17 19:00 tty27
< crw--w----   1 root   tty         4,    28 Jul 17 19:00 tty28
< crw--w----   1 root   tty         4,    29 Jul 17 19:00 tty29
< crw--w----   1 root   tty         4,     3 Jul 17 19:00 tty3
< crw--w----   1 root   tty         4,    30 Jul 17 19:00 tty30
< crw--w----   1 root   tty         4,    31 Jul 17 19:00 tty31
< crw--w----   1 root   tty         4,    32 Jul 17 19:00 tty32
< crw--w----   1 root   tty         4,    33 Jul 17 19:00 tty33
< crw--w----   1 root   tty         4,    34 Jul 17 19:00 tty34
< crw--w----   1 root   tty         4,    35 Jul 17 19:00 tty35
< crw--w----   1 root   tty         4,    36 Jul 17 19:00 tty36
< crw--w----   1 root   tty         4,    37 Jul 17 19:00 tty37
< crw--w----   1 root   tty         4,    38 Jul 17 19:00 tty38
< crw--w----   1 root   tty         4,    39 Jul 17 19:00 tty39
< crw--w----   1 root   tty         4,     4 Jul 17 19:00 tty4
< crw--w----   1 root   tty         4,    40 Jul 17 19:00 tty40
< crw--w----   1 root   tty         4,    41 Jul 17 19:00 tty41
< crw--w----   1 root   tty         4,    42 Jul 17 19:00 tty42
< crw--w----   1 root   tty         4,    43 Jul 17 19:00 tty43
< crw--w----   1 root   tty         4,    44 Jul 17 19:00 tty44
< crw--w----   1 root   tty         4,    45 Jul 17 19:00 tty45
< crw--w----   1 root   tty         4,    46 Jul 17 19:00 tty46
< crw--w----   1 root   tty         4,    47 Jul 17 19:00 tty47
< crw--w----   1 root   tty         4,    48 Jul 17 19:00 tty48
< crw--w----   1 root   tty         4,    49 Jul 17 19:00 tty49
< crw--w----   1 root   tty         4,     5 Jul 17 19:00 tty5
< crw--w----   1 root   tty         4,    50 Jul 17 19:00 tty50
< crw--w----   1 root   tty         4,    51 Jul 17 19:00 tty51
< crw--w----   1 root   tty         4,    52 Jul 17 19:00 tty52
< crw--w----   1 root   tty         4,    53 Jul 17 19:00 tty53
< crw--w----   1 root   tty         4,    54 Jul 17 19:00 tty54
< crw--w----   1 root   tty         4,    55 Jul 17 19:00 tty55
< crw--w----   1 root   tty         4,    56 Jul 17 19:00 tty56
< crw--w----   1 root   tty         4,    57 Jul 17 19:00 tty57
< crw--w----   1 root   tty         4,    58 Jul 17 19:00 tty58
< crw--w----   1 root   tty         4,    59 Jul 17 19:00 tty59
< crw--w----   1 root   tty         4,     6 Jul 17 19:00 tty6
< crw--w----   1 root   tty         4,    60 Jul 17 19:00 tty60
< crw--w----   1 root   tty         4,    61 Jul 17 19:00 tty61
< crw--w----   1 root   tty         4,    62 Jul 17 19:00 tty62
< crw--w----   1 root   tty         4,    63 Jul 17 19:00 tty63
< crw--w----   1 root   tty         4,     7 Jul 17 19:00 tty7
< crw--w----   1 root   tty         4,     8 Jul 17 19:00 tty8
< crw--w----   1 root   tty         4,     9 Jul 17 19:00 tty9
< crw-------   1 root   root        5,     3 Jul 17 19:00 ttyprintk
< crw-rw----   1 root   dialout     4,    64 Jul 17 19:00 ttyS0
< crw-rw----   1 root   dialout     4,    65 Jul 17 19:00 ttyS1
< crw-rw----   1 root   dialout     4,    74 Jul 17 19:00 ttyS10
< crw-rw----   1 root   dialout     4,    75 Jul 17 19:00 ttyS11
< crw-rw----   1 root   dialout     4,    76 Jul 17 19:00 ttyS12
< crw-rw----   1 root   dialout     4,    77 Jul 17 19:00 ttyS13
< crw-rw----   1 root   dialout     4,    78 Jul 17 19:00 ttyS14
< crw-rw----   1 root   dialout     4,    79 Jul 17 19:00 ttyS15
< crw-rw----   1 root   dialout     4,    80 Jul 17 19:00 ttyS16
< crw-rw----   1 root   dialout     4,    81 Jul 17 19:00 ttyS17
< crw-rw----   1 root   dialout     4,    82 Jul 17 19:00 ttyS18
< crw-rw----   1 root   dialout     4,    83 Jul 17 19:00 ttyS19
< crw-rw----   1 root   dialout     4,    66 Jul 17 19:00 ttyS2
< crw-rw----   1 root   dialout     4,    84 Jul 17 19:00 ttyS20
< crw-rw----   1 root   dialout     4,    85 Jul 17 19:00 ttyS21
< crw-rw----   1 root   dialout     4,    86 Jul 17 19:00 ttyS22
< crw-rw----   1 root   dialout     4,    87 Jul 17 19:00 ttyS23
< crw-rw----   1 root   dialout     4,    88 Jul 17 19:00 ttyS24
< crw-rw----   1 root   dialout     4,    89 Jul 17 19:00 ttyS25
< crw-rw----   1 root   dialout     4,    90 Jul 17 19:00 ttyS26
< crw-rw----   1 root   dialout     4,    91 Jul 17 19:00 ttyS27
< crw-rw----   1 root   dialout     4,    92 Jul 17 19:00 ttyS28
< crw-rw----   1 root   dialout     4,    93 Jul 17 19:00 ttyS29
< crw-rw----   1 root   dialout     4,    67 Jul 17 19:00 ttyS3
< crw-rw----   1 root   dialout     4,    94 Jul 17 19:00 ttyS30
< crw-rw----   1 root   dialout     4,    95 Jul 17 19:00 ttyS31
< crw-rw----   1 root   dialout     4,    68 Jul 17 19:00 ttyS4
< crw-rw----   1 root   dialout     4,    69 Jul 17 19:00 ttyS5
< crw-rw----   1 root   dialout     4,    70 Jul 17 19:00 ttyS6
< crw-rw----   1 root   dialout     4,    71 Jul 17 19:00 ttyS7
< crw-rw----   1 root   dialout     4,    72 Jul 17 19:00 ttyS8
< crw-rw----   1 root   dialout     4,    73 Jul 17 19:00 ttyS9
< crw-rw----   1 root   kvm        10,   259 Jul 17 19:00 udmabuf
< crw-------   1 root   root       10,   239 Jul 17 19:00 uhid
< crw-------   1 root   root       10,   223 Jul 17 19:00 uinput
< crw-rw-rw-   1 root   root        1,     9 Jul 17 19:00 urandom
< crw-------   1 root   root       10,   257 Jul 17 19:00 userfaultfd
< crw-------   1 root   root       10,   240 Jul 17 19:00 userio
< drwxr-xr-x   4 root   root              80 Jul 17 19:00 v4l
< crw-------   1 root   root       10,   261 Jul 17 19:00 vboxdrv
< crw-rw-rw-   1 root   root       10,   262 Jul 17 19:00 vboxdrvu
< crw-------   1 root   root       10,   263 Jul 17 19:00 vboxnetctl
< drwxr-x---   4 root   vboxusers         80 Jul 17 19:00 vboxusb
< crw-rw----   1 root   tty         7,     0 Jul 17 19:00 vcs
< crw-rw----   1 root   tty         7,     1 Jul 17 19:00 vcs1
< crw-rw----   1 root   tty         7,     2 Jul 17 19:00 vcs2
< crw-rw----   1 root   tty         7,     3 Jul 17 19:00 vcs3
< crw-rw----   1 root   tty         7,     4 Jul 17 19:00 vcs4
< crw-rw----   1 root   tty         7,     5 Jul 17 19:00 vcs5
< crw-rw----   1 root   tty         7,     6 Jul 17 19:00 vcs6
< crw-rw----   1 root   tty         7,   128 Jul 17 19:00 vcsa
< crw-rw----   1 root   tty         7,   129 Jul 17 19:00 vcsa1
< crw-rw----   1 root   tty         7,   130 Jul 17 19:00 vcsa2
< crw-rw----   1 root   tty         7,   131 Jul 17 19:00 vcsa3
< crw-rw----   1 root   tty         7,   132 Jul 17 19:00 vcsa4
< crw-rw----   1 root   tty         7,   133 Jul 17 19:00 vcsa5
< crw-rw----   1 root   tty         7,   134 Jul 17 19:00 vcsa6
< crw-rw----   1 root   tty         7,    64 Jul 17 19:00 vcsu
< crw-rw----   1 root   tty         7,    65 Jul 17 19:00 vcsu1
< crw-rw----   1 root   tty         7,    66 Jul 17 19:00 vcsu2
< crw-rw----   1 root   tty         7,    67 Jul 17 19:00 vcsu3
< crw-rw----   1 root   tty         7,    68 Jul 17 19:00 vcsu4
< crw-rw----   1 root   tty         7,    69 Jul 17 19:00 vcsu5
< crw-rw----   1 root   tty         7,    70 Jul 17 19:00 vcsu6
< drwxr-xr-x   2 root   root              60 Jul 17 19:00 vfio
< crw-------   1 root   root       10,   256 Jul 17 19:00 vga_arbiter
< crw-------   1 root   root       10,   137 Jul 17 19:00 vhci
< crw-rw----   1 root   kvm        10,   238 Jul 17 22:24 vhost-net
< crw-rw----   1 root   kvm        10,   241 Jul 17 22:24 vhost-vsock
< crw-rw----+  1 root   video      81,     0 Jul 17 19:00 video0
< crw-rw----+  1 root   video      81,     1 Jul 17 19:00 video1
< crw-rw-rw-   1 root   root       10,   264 Jul 17 22:24 vsock
< crw-rw-rw-   1 root   root        1,     5 Jul 17 19:00 zero
< crw-------   1 root   root       10,   249 Jul 17 19:00 zfs
---
> drwxr-xr-x    5 root     root           320 Jul 17 20:08 .
> drwxr-xr-x    1 root     root          4096 Jul 17 20:08 ..
> lrwxrwxrwx    1 root     root            13 Jul 17 20:08 fd -> /proc/self/fd
> crw-rw-rw-    1 root     root        1,   7 Jul 17 20:08 full
> drwxrwxrwt    2 root     root            40 Jul 17 20:08 mqueue
> crw-rw-rw-    1 root     root        1,   3 Jul 17 20:08 null
> lrwxrwxrwx    1 root     root             8 Jul 17 20:08 ptmx -> pts/ptmx
> drwxr-xr-x    2 root     root             0 Jul 17 20:08 pts
> crw-rw-rw-    1 root     root        1,   8 Jul 17 20:08 random
> drwxrwxrwt    2 root     root            40 Jul 17 20:08 shm
> lrwxrwxrwx    1 root     root            15 Jul 17 20:08 stderr -> /proc/self/fd/2
> lrwxrwxrwx    1 root     root            15 Jul 17 20:08 stdin -> /proc/self/fd/0
> lrwxrwxrwx    1 root     root            15 Jul 17 20:08 stdout -> /proc/self/fd/1
> crw-rw-rw-    1 root     root        5,   0 Jul 17 20:08 tty
> crw-rw-rw-    1 root     root        1,   9 Jul 17 20:08 urandom
> crw-rw-rw-    1 root     root        1,   5 Jul 17 20:08 zero

```
host exposes many device nodes, while kata exposes only 15.

### Isolation: capability sets
runc:
```
CapInh:	0000000000000000
CapPrm:	000001ffffffffff
CapEff:	000001ffffffffff
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

```
kata:
```
CapInh:	0000000000000000
CapPrm:	00000000a80425fb
CapEff:	00000000a80425fb
CapBnd:	00000000a80425fb
CapAmb:	0000000000000000
```

### Startup time (5-run avg)
| Runtime | Avg startup (s) |
|---------|----------------:|
| runc | could not measure properly due to a shim issue |
| kata | 1.40 |

**Overhead: could not calculate**

### I/O throughput (100MB dd)
| Runtime | Throughput |
|---------|-----------|
| runc | 20.5 GB/s> |
| kata | 18.9 GB/s> |

### Trade-off analysis (3-4 sentences, Reading 12 framing)
When is the security gain (separate kernel, runc-CVE class blocked) worth the cost?
When isn't it? Give one example each (e.g., "multi-tenant SaaS workloads = yes;
single-tenant batch jobs = no").

Security gain is worth the cost when single host compromise is fatal, multi-tenant SaaS. Also for regular environments that require isolation like VM. Not worth for single-tenant jobs or trusted internal services, where everything is fully controlled, since kata has 80Mb per-container memory overhead.
