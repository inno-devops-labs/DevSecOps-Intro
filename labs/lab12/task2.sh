echo "=== Kata Container Tests ==="
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee labs/lab12/kata/test1.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r | tee labs/lab12/kata/kernel.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1" | tee labs/lab12/kata/cpu.txt

echo "=== Kernel Version Comparison ===" | tee labs/lab12/analysis/kernel-comparison.txt
echo -n "Host kernel (runc uses this): " | tee -a labs/lab12/analysis/kernel-comparison.txt
uname -r | tee -a labs/lab12/analysis/kernel-comparison.txt

echo -n "Kata guest kernel: " | tee -a labs/lab12/analysis/kernel-comparison.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 cat /proc/version | tee -a labs/lab12/analysis/kernel-comparison.txt

echo "=== CPU Model Comparison ===" | tee labs/lab12/analysis/cpu-comparison.txt
echo "Host CPU:" | tee -a labs/lab12/analysis/cpu-comparison.txt
grep "model name" /proc/cpuinfo | head -1 | tee -a labs/lab12/analysis/cpu-comparison.txt

echo "Kata VM CPU:" | tee -a labs/lab12/analysis/cpu-comparison.txt
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1" | tee -a labs/lab12/analysis/cpu-comparison.txt