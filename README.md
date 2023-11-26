# Susspekt

Sniffs TLS traffic on the network, and tracks JA3's making new connections. Aggregates http handshake rates based on `{ja3}-{remote_addr}`, and if thresholds are violated, posts the 
suspect `{ja3}-{remote_addr}` to a rest endpoint as a simple json object:

```json
{
    "key": "579ccef312d18482fc42e2b822ca2430-192.168.0.7",
    "block_time": 86400,
    "realert": "false"
}
```

## Usage

```bash
Usage: susspekt <--interface <INTERFACE>|--pcap-file <PCAP_FILE>|--threshold <THRESHOLD>|--window <WINDOW>|--alert-url <ALERT_URL>|--alert-fake-mode <ALERT_FAKE_MODE>|--block-seconds <BLOCK_SECONDS>|--whitelist-networks <WHITELIST_NETWORKS>|--whitelist-ja3s <WHITELIST_JA3S>|--log-create-buckets <LOG_CREATE_BUCKETS>>

Options:
      --interface <INTERFACE>
          network device for pcap listening, e.g: eth0
  -p, --pcap-file <PCAP_FILE>
          pcap dump for testing, not yet implemented
  -t, --threshold <THRESHOLD>
          Threshold number of occurrences of a ja3-remote_addr-uri in the window [default: 1000]
  -w, --window <WINDOW>
          Time window in seconds for calculating the threshold [default: 60]
  -a, --alert-url <ALERT_URL>
          The endpoint for updating the block list [default: http://localhost:8080/api/block/update]
      --alert-fake-mode <ALERT_FAKE_MODE>
          Pretend the ELB accepted the payload [possible values: true, false]
  -b, --block-seconds <BLOCK_SECONDS>
          Alert duration field value in seconds for how long to block suspicious traffic [default: 86400]
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

# Building

```bash
cargo build --release
```

# Log output

```

2023-11-26T08:41:10.492712Z: INFO - susspekt-wire-sniffer
2023-11-26T08:41:14.083062Z: INFO - Source: 192.168.0.7, Destination: 83.255.219.16, JA3: 0401c0b25dff8b94bcb822b4b2e6d75b-192.168.0.7, Packet Size: 569, Is Handshake: true
2023-11-26T08:41:14.083952Z: INFO - Source: 192.168.0.7, Destination: 108.157.229.40, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Packet Size: 572, Is Handshake: true
2023-11-26T08:41:14.084175Z: INFO - Source: 192.168.0.7, Destination: 34.36.212.39, JA3: 579ccef312d18482fc42e2b822ca2430-192.168.0.7, Packet Size: 569, Is Handshake: true
2023-11-26T08:41:14.084493Z: INFO - Source: 192.168.0.7, Destination: 34.36.212.39, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Packet Size: 707, Is Handshake: true
2023-11-26T08:41:14.084681Z: INFO - Threshold violation, threshold: 1 exceeded within 10 seconds, for ja3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7
2023-11-26T08:41:14.084775Z: INFO - Bucket key: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Last Timestamp: SystemTime { tv_sec: 1700988074, tv_nsec: 84638997 }, Rolling Values: [2], Total Count: 2
2023-11-26T08:41:14.084841Z: WARN - Alerting for "c279b0189edb9269da7bc43dea5e0c36-192.168.0.7"
2023-11-26T08:41:14.087836Z: WARN - Alert sent...
2023-11-26T08:41:14.871482Z: INFO - Source: 192.168.0.7, Destination: 65.9.55.3, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Packet Size: 570, Is Handshake: true
2023-11-26T08:41:14.871691Z: INFO - Source: 192.168.0.7, Destination: 34.36.212.39, JA3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Packet Size: 707, Is Handshake: true
2023-11-26T08:41:14.871699Z: INFO - Threshold violation, threshold: 1 exceeded within 10 seconds, for ja3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7
2023-11-26T08:41:14.871753Z: INFO - Bucket key: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Last Timestamp: SystemTime { tv_sec: 1700988074, tv_nsec: 871665394 }, Rolling Values: [3], Total Count: 3
2023-11-26T08:41:14.871792Z: INFO - Threshold violation, threshold: 1 exceeded within 10 seconds, for ja3: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7
2023-11-26T08:41:14.871802Z: INFO - Bucket key: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, Last Timestamp: SystemTime { tv_sec: 1700988074, tv_nsec: 871789280 }, Rolling Values: [4], Total Count: 4
2023-11-26T08:41:14.871833Z: WARN - Last alert for key: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, was at: SystemTime { tv_sec: 1700988074, tv_nsec: 87865596 }
2023-11-26T08:41:14.871842Z: WARN - Supressing alert, last alert for key: c279b0189edb9269da7bc43dea5e0c36-192.168.0.7, was at: SystemTime { tv_sec: 1700988074, tv_nsec: 87865596 }, elapsed time since then: 783.975432ms

```
