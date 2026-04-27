echo "=== Startup Time Comparison ===" | tee labs/lab12/bench/startup.txt

echo "runc:" | tee -a labs/lab12/bench/startup.txt
time sudo nerdctl run --rm alpine:3.19 echo "test" 2>&1 | grep real | tee -a labs/lab12/bench/startup.txt

echo "Kata:" | tee -a labs/lab12/bench/startup.txt
time sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "test" 2>&1 | grep real | tee -a labs/lab12/bench/startup.txt

echo "=== HTTP Latency Test (juice-runc) ===" | tee labs/lab12/bench/http-latency.txt
out="labs/lab12/bench/curl-3012.txt"
: > "$out"

for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{time_total}\n" http://localhost:3012/ >> "$out"
done

echo "Results for port 3012 (juice-runc):" | tee -a labs/lab12/bench/http-latency.txt
awk '{s+=$1; n+=1} END {if(n>0) printf "avg=%.4fs min=%.4fs max=%.4fs n=%d\n", s/n, min, max, n}' \
  min=$(sort -n "$out" | head -1) max=$(sort -n "$out" | tail -1) "$out" | tee -a labs/lab12/bench/http-latency.txt