echo "=== dmesg Access Test ===" | tee labs/lab12/isolation/dmesg.txt

echo "Kata VM (separate kernel boot logs):" | tee -a labs/lab12/isolation/dmesg.txt  
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 dmesg 2>&1 | head -5 | tee -a labs/lab12/isolation/dmesg.txt

echo "=== /proc Entries Count ===" | tee labs/lab12/isolation/proc.txt

echo -n "Host: " | tee -a labs/lab12/isolation/proc.txt
ls /proc | wc -l | tee -a labs/lab12/isolation/proc.txt

echo -n "Kata VM: " | tee -a labs/lab12/isolation/proc.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /proc | wc -l" | tee -a labs/lab12/isolation/proc.txt

echo "=== Network Interfaces ===" | tee labs/lab12/isolation/network.txt

echo "Kata VM network:" | tee -a labs/lab12/isolation/network.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 ip addr | tee -a labs/lab12/isolation/network.txt

echo "=== Kernel Modules Count ===" | tee labs/lab12/isolation/modules.txt

echo -n "Host kernel modules: " | tee -a labs/lab12/isolation/modules.txt
ls /sys/module | wc -l | tee -a labs/lab12/isolation/modules.txt

echo -n "Kata guest kernel modules: " | tee -a labs/lab12/isolation/modules.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /sys/module 2>/dev/null | wc -l" | tee -a labs/lab12/isolation/modules.txt