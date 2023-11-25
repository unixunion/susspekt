# Susspekt

Sniffs TLS traffic on the network, and tracks JA3's making new connections. 
It aggregates based on source + ja3, and if thresholds are violated, posts the 
suspect ja3 to a rest endpoint.

# Building

* cargo build

# Running

```
sudo ./target/debug/sniffer --network wlo1 --threshold 1000 --window 60 
2023-11-25T15:15:53.315290Z: INFO - susspekt-wire-sniffer
2023-11-25T15:15:58.024262Z: INFO - Source: 192.168.0.55, Destination: 142.250.74.106, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.55, Packet Size: 569, Is Handshake: true
2023-11-25T15:15:58.024493Z: INFO - Source: 192.168.0.55, Destination: 142.250.74.78, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 712, Is Handshake: true
2023-11-25T15:15:58.024641Z: INFO - Source: 192.168.0.55, Destination: 35.244.233.98, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.55, Packet Size: 701, Is Handshake: true
2023-11-25T15:15:58.024762Z: INFO - Source: 192.168.0.55, Destination: 83.255.218.208, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.55, Packet Size: 569, Is Handshake: true
2023-11-25T15:15:58.024893Z: INFO - Source: 192.168.0.55, Destination: 216.58.211.3, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.55, Packet Size: 569, Is Handshake: true
2023-11-25T15:15:58.025172Z: INFO - Source: 192.168.0.55, Destination: 35.190.26.106, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.55, Packet Size: 569, Is Handshake: true
2023-11-25T15:15:58.340540Z: INFO - Source: 192.168.0.55, Destination: 142.250.74.46, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 721, Is Handshake: true
2023-11-25T15:15:58.340627Z: INFO - Source: 192.168.0.55, Destination: 172.217.21.163, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 714, Is Handshake: true
2023-11-25T15:15:58.340669Z: INFO - Source: 192.168.0.55, Destination: 142.250.74.110, JA3: 02aa4679df284f240695da144b70c288-192.168.0.55, Packet Size: 712, Is Handshake: true

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