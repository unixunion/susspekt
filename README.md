# Susspekt

Sniffs TLS traffic on the network, and tracks JA3's making new connections. 
It aggregates based on source + ja3, and if thresholds are violated, posts the 
suspect ja3 to a rest endpoint.

# Building

* cargo build

# Running

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