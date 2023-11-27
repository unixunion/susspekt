# Susspekt

Sniffs TLS traffic on the network, and tracks JA3's making new connections. Aggregates http handshake rates based on 
`{ja3}` or `{ja3}-{remote_addr}`, and if thresholds are violated, posts the suspect `{ja3}`/`{ja3}-{remote_addr}` to a 
rest endpoint as a simple json object:

```json
{
    "key": "579ccef312d18482fc42e2b822ca2430-192.168.0.7",
    "block_time": 86400,
    "realert": "false"
}
```

## Usage

```bash
Usage: susspekt <--interface <INTERFACE>|--file <FILE>|--threshold <THRESHOLD>|--window <WINDOW>|--alert-url <ALERT_URL>|--dry-run|--block-seconds <BLOCK_SECONDS>|--whitelist-networks <WHITELIST_NETWORKS>|--whitelist-ja3s <WHITELIST_JA3S>|--log-create-buckets <LOG_CREATE_BUCKETS>|--agg-ip|--log-config <LOG_CONFIG>>

Options:
  -i, --interface <INTERFACE>
          Network device to sniff, e.g: eth0
  -f, --file <FILE>
          The pcap file to analyse for testing. NOTE: timing windows dont work with files
  -t, --threshold <THRESHOLD>
          Threshold number of occurrences of a ja3-remote_addr-uri in the window [default: 1000]
  -w, --window <WINDOW>
          Time window in seconds for calculating the threshold [default: 60]
  -a, --alert-url <ALERT_URL>
          The endpoint for updating the block list [default: http://localhost:8080/api/block/update]
  -d, --dry-run
          DryRun disables posting the alerts to the --alert-url
  -b, --block-seconds <BLOCK_SECONDS>
          Alert duration field value in seconds for how long to block suspicious traffic [default: 86400]
      --whitelist-networks <WHITELIST_NETWORKS>
          Comma-separated list of whitelisted networks in CIDR notation [default: "10.0.0.0/8, 192.168.0.0/16"]
      --whitelist-ja3s <WHITELIST_JA3S>
          Optional comma-separated list of whitelisted md5_semi_ja3 [default: None]
      --log-create-buckets <LOG_CREATE_BUCKETS>
          enable logging for new buckets [possible values: true, false]
      --agg-ip
          add IP to the ja3 hash as a key to aggregate on, e.g: {ja3}-{remote_addr}
      --log-config <LOG_CONFIG>
          Config file for log4rs [default: /etc/susspekt/log4rs.yaml]
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
2023-11-27T09:14:25.288728Z: INFO - {"source":"192.168.0.7","destination":"34.149.100.209","ja3":"579ccef312d18482fc42e2b822ca2430","packet_size":569,"is_handshake":true,"ethernet_frame_size":583,"is_syn":false,"is_fin":false,"is_rst":false}
2023-11-27T09:14:25.288749Z: INFO - Threshold violation, threshold: 1 exceeded within 10 seconds, for ja3: 579ccef312d18482fc42e2b822ca2430
2023-11-27T09:14:25.288758Z: INFO - {"source":"192.168.0.7","destination":"216.58.207.194","ja3":"None-192.168.0.7","packet_size":60,"is_handshake":false,"ethernet_frame_size":74,"is_syn":true,"is_fin":false,"is_rst":false}
2023-11-27T09:14:25.288767Z: INFO - {"source":"192.168.0.7","destination":"216.58.207.194","ja3":"None-192.168.0.7","packet_size":60,"is_handshake":false,"ethernet_frame_size":74,"is_syn":true,"is_fin":false,"is_rst":false}
2023-11-27T09:14:25.288770Z: INFO - Bucket key: 579ccef312d18482fc42e2b822ca2430, Last Timestamp: SystemTime { tv_sec: 1701076465, tv_nsec: 288738671 }, Rolling Values: [2], Total Count: 2
2023-11-27T09:14:25.288792Z: WARN - Alerting for "579ccef312d18482fc42e2b822ca2430"
2023-11-27T09:14:25.288798Z: INFO - {"source":"192.168.0.7","destination":"216.58.207.194","ja3":"579ccef312d18482fc42e2b822ca2430","packet_size":569,"is_handshake":true,"ethernet_frame_size":583,"is_syn":false,"is_fin":false,"is_rst":false}
2023-11-27T09:14:25.288798Z: INFO - Posting alert to: http://localhost:8080/api/block/update
2023-11-27T09:14:25.288829Z: INFO - {"source":"192.168.0.7","destination":"216.58.207.194","ja3":"579ccef312d18482fc42e2b822ca2430","packet_size":569,"is_handshake":true,"ethernet_frame_size":583,"is_syn":false,"is_fin":false,"is_rst":false}
```
