# Susspekt

Sniffs TLS traffic on the network, and tracks JA3's making new connections. 
It aggregates based on source + ja3, and if thresholds are violated, posts the 
suspect ja3 to a rest endpoint.

# Building

* cargo build

# Running

```
sudo susspekt --network wlo1 --threshold 1000 --window 60 
2023-11-25T15:27:53.599413Z: INFO - susspekt-wire-sniffer
2023-11-25T15:27:57.511841Z: INFO - Source: 192.168.0.55, Destination: 151.101.84.143, JA3: e669667efb41c36f714c309243f41ca7-192.168.0.55, Packet Size: 624, Is Handshake: true
2023-11-25T15:27:57.511923Z: INFO - Source: 192.168.0.55, Destination: 83.255.218.51, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.55, Packet Size: 712, Is Handshake: true
2023-11-25T15:27:58.352895Z: INFO - Source: 192.168.0.55, Destination: 142.250.74.102, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 715, Is Handshake: true
...
2023-11-25T15:27:58.352898Z: INFO - Threshold violation, threshold: 10 exceeded within 60 seconds, for ja3: 02aa4679df284f240695da144b70c288-192.168.0.55
2023-11-25T15:27:58.352914Z: INFO - Bucket key: 02aa4679df284f240695da144b70c288-192.168.0.55, Last Timestamp: SystemTime { tv_sec: 1700926078, tv_nsec: 352898029 }, Rolling Values: [11], Total Count: 11
2023-11-25T15:27:58.352923Z: INFO - Posting block rule payload: { "02aa4679df284f240695da144b70c288-192.168.0.55": 86400 }
2023-11-25T15:27:58.356530Z: INFO - Response from NGINX: "Received POST data"
2023-11-25T15:27:58.356543Z: INFO - Block rule posted successfully for ja3 "02aa4679df284f240695da144b70c288-192.168.0.55"
2023-11-25T15:27:58.356594Z: INFO - Source: 192.168.0.55, Destination: 52.223.40.198, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.55, Packet Size: 569, Is Handshake: true
2023-11-25T15:27:58.356625Z: INFO - Source: 192.168.0.55, Destination: 31.13.72.12, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 614, Is Handshake: true
2023-11-25T15:27:58.356628Z: WARN - Suppressing re-alert for ja3: 02aa4679df284f240695da144b70c288-192.168.0.55

```

# Usage

```bash
Usage: sniffer [OPTIONS]

Options:
      --network <NETWORK>
          network device for pcap listening, e.g: eth0
  -p, --pack-file <PACK_FILE>
          pcap dump for testing [default: idontexist.pcap]
  -t, --threshold <THRESHOLD>
          Threshold number of occurrences of a ja3-remote_addr-uri in the window [default: 1000]
  -w, --window <WINDOW>
          Time window in seconds for calculating the threshold [default: 30]
  -e, --elb-host <ELB_HOST>
          The endpoint for updating the block list [default: https://localhost:8443/api/block/update]
      --elb-fake-mode <ELB_FAKE_MODE>
          Pretend the ELB accepted the payload [possible values: true, false]
  -b, --block-seconds <BLOCK_SECONDS>
          Duration in seconds for how long to block suspicious traffic [default: 86400]
      --whitelist-networks <WHITELIST_NETWORKS>
          Comma-separated list of whitelisted networks in CIDR notation [default: "10.0.0.0/8, 192.168.0.0/16"]
      --whitelist-ja3s <WHITELIST_JA3S>
          Optional comma-separated list of whitelisted md5_semi_ja3
      --log-create-buckets <LOG_CREATE_BUCKETS>
          enable logging for new buckets [possible values: true, false]
  -h, --help
          Print help
  -V, --version
          Print version

```