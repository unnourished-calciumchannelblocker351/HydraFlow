# Crowdsourced Blocking Map

The blocking map is HydraFlow's crowdsourced intelligence system that tracks which proxy protocols work on which ISPs. It aggregates anonymous reports from clients to build a real-time picture of censorship conditions across different networks.

## How It Works

### Data Collection

Clients optionally report their connection results:
- **AS Number** (Autonomous System) -- identifies the ISP without revealing the user's IP
- **Protocol name** -- which protocol was tested (e.g., "reality-vision", "xhttp-cdn")
- **Status** -- working, slow, or blocked
- **Latency** (optional) -- observed connection time

Reports are anonymized at the client before transmission. Only the AS number is sent -- never the client's IP address, geographic location, or any identifying information.

### Aggregation

Reports are aggregated per ISP (identified by AS number) and per protocol. The system uses **exponential time decay** to ensure recent reports carry more weight than old ones:

```
weight = 2^(-(now - report_time) / half_life)
```

The default half-life is 24 hours, meaning a report from yesterday has half the influence of a report from right now. A report from 3 days ago has roughly 1/8th the weight.

The dominant status (working/slow/blocked) is determined by weighted majority vote across all reports for that ISP+protocol pair. A confidence score (0.0 to 1.0) indicates how much agreement there is among reports.

### Recommendations

When a client requests recommendations for their ISP, the blocking map returns all known protocols sorted by score:

| Status | Base Score |
|---------|-----------|
| Working | 1.0 |
| Slow | 0.5 |
| Blocked | 0.0 |
| Unknown | 0.3 |

The final score blends the base score with confidence: protocols that are confidently working score highest, while protocols with mixed reports score closer to 0.5 (neutral).

## Privacy Guarantees

### What Is Collected
- AS Number (public information about the ISP)
- Protocol name and status
- Timestamp (truncated to the hour)
- Latency (optional, rounded)

### What Is Never Collected
- IP addresses
- Geographic coordinates
- Device identifiers
- Connection targets or destinations
- Any personally identifiable information

### Double Encryption (OHTTP-like)

Reports use a double-encryption scheme inspired by Oblivious HTTP:

1. The report is encrypted for the **collector** (inner layer)
2. The encrypted report is encrypted again for the **relay** (outer layer)
3. The client sends the doubly-encrypted report to the relay
4. The relay strips its encryption layer and forwards to the collector
5. The collector decrypts the inner layer to read the report

This ensures:
- The **relay** sees the client's IP but cannot read the report content
- The **collector** reads the report content but never sees the client's IP
- No single party has both the client's identity and their report data

### Opt-In Only

Telemetry is **disabled by default**. Users must explicitly enable it:

```yaml
telemetry:
  enabled: true
  endpoint: "https://telemetry.example.com/report"
  report_interval: "5m"
```

Users can disable reporting at any time. When disabled, all pending reports are discarded immediately.

## Data Format

### Block Report (JSON)

```json
{
  "as_number": 12345,
  "isp_name": "Example ISP",
  "protocol": "reality-vision",
  "status": 1,
  "latency": 150000000,
  "timestamp": "2025-01-15T12:00:00Z"
}
```

Status values:
- `0` -- Unknown
- `1` -- Working
- `2` -- Slow
- `3` -- Blocked

### Serialized BlockMap (JSON)

```json
{
  "isps": {
    "12345": {
      "as_number": 12345,
      "isp_name": "Example ISP",
      "protocols": {
        "reality-vision": {
          "reports": [
            {"status": 1, "timestamp": "2025-01-15T12:00:00Z"},
            {"status": 1, "timestamp": "2025-01-15T11:00:00Z"}
          ]
        }
      }
    }
  },
  "decay_half_life_seconds": 86400,
  "max_reports_per_protocol": 100
}
```

### Recommendation Response

```json
[
  {"protocol": "reality-vision", "status": 1, "score": 0.95},
  {"protocol": "xhttp-cdn", "status": 1, "score": 0.85},
  {"protocol": "hysteria2", "status": 3, "score": 0.05}
]
```

## API

### BlockMap

```go
// Create a new blocking map.
bm := discovery.NewBlockMap()

// Add a report.
bm.AddReport(discovery.BlockReport{
    ASNumber:  12345,
    ISPName:   "Example ISP",
    Protocol:  "reality-vision",
    Status:    discovery.StatusWorking,
    Timestamp: time.Now(),
})

// Get status for a specific ISP + protocol.
status, confidence := bm.GetStatus(12345, "reality-vision")

// Get recommendations for an ISP (sorted by score).
recs := bm.Recommend(12345)

// Serialize to JSON for persistence.
data, _ := json.Marshal(bm)

// Deserialize from JSON.
bm2 := discovery.NewBlockMap()
json.Unmarshal(data, bm2)

// Prune old reports.
removed := bm.Prune(7 * 24 * time.Hour)
```

### ISPDetector

```go
// Create a detector and register known AS numbers.
detector := discovery.NewISPDetector()
detector.Register(12345, "Example ISP")
detector.RegisterBulk(map[uint32]string{
    25513: "Rostelecom",
    8359:  "MTS",
})

// Look up an ISP by AS number.
name, found := detector.Lookup(25513) // "Rostelecom", true
```

### Reporter

```go
// Create an anonymous reporter.
reporter := discovery.NewReporter(discovery.ReporterConfig{
    Endpoint:      "https://telemetry.example.com/report",
    BatchSize:     10,
    FlushInterval: 5 * time.Minute,
    Enabled:       true,
})

reporter.Start()
defer reporter.Stop()

// Report a connection result.
reporter.Report(12345, "reality-vision", discovery.StatusWorking, 150*time.Millisecond)

// Toggle reporting at runtime.
reporter.SetEnabled(false)
```

## Configuration

The blocking map is configured through the main HydraFlow config:

```yaml
telemetry:
  enabled: true
  endpoint: "https://telemetry.example.com/report"
  report_interval: "5m"
```

Server-side, the blocking map can be distributed as part of the subscription format:

```yaml
blocking_map:
  rostelecom:
    blocked: [quic, wireguard]
    recommended: [reality-vision, xhttp-cdn]
    notes: "QUIC blocked since March 2024"
  mts:
    recommended: [reality-vision]
```

## Thread Safety

All BlockMap, ISPDetector, and Reporter operations are safe for concurrent use from multiple goroutines. The BlockMap uses a read-write mutex to allow concurrent reads while serializing writes.
