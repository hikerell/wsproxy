# WSProxy

## Benchmark

Use `/Users/hikerell/Workspace/wsproxy/scripts/wsproxy_bench.py` to stress test TCP proxy performance through the local SOCKS5 endpoint.

Run echo server on target side:

```bash
python3 ./scripts/wsproxy_bench.py echo-server --host 0.0.0.0 --port 19090
```

Run benchmark from client side (through wsproxy SOCKS5):

```bash
python3 ./scripts/wsproxy_bench.py tcp-bench \
  --socks-host 127.0.0.1 \
  --socks-port 1080 \
  --target-host <TARGET_IP_OR_DOMAIN> \
  --target-port 19090 \
  --connections 128 \
  --duration 30 \
  --payload-size 1024 \
  --mode echo \
  --verify-echo
```

The script reports connection success rate, request rate, throughput (MiB/s), and sampled latency percentiles (p50/p95/p99).
