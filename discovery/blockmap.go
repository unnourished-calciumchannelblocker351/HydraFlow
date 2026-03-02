package discovery

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

// ProtocolStatus represents the operational state of a protocol on a given ISP.
type ProtocolStatus int

const (
	// StatusUnknown means no reports have been received yet.
	StatusUnknown ProtocolStatus = iota
	// StatusWorking means the protocol is confirmed working.
	StatusWorking
	// StatusSlow means the protocol works but with degraded performance.
	StatusSlow
	// StatusBlocked means the protocol is confirmed blocked.
	StatusBlocked
)

// String returns a human-readable name for the status.
func (s ProtocolStatus) String() string {
	switch s {
	case StatusWorking:
		return "working"
	case StatusSlow:
		return "slow"
	case StatusBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// ParseProtocolStatus converts a string to a ProtocolStatus.
func ParseProtocolStatus(s string) ProtocolStatus {
	switch s {
	case "working":
		return StatusWorking
	case "slow":
		return StatusSlow
	case "blocked":
		return StatusBlocked
	default:
		return StatusUnknown
	}
}

// BlockReport is a single anonymized report from a client.
type BlockReport struct {
	// ASNumber is the autonomous system number identifying the ISP.
	ASNumber uint32 `json:"as_number"`

	// ISPName is a human-readable name for the ISP (optional, derived from AS).
	ISPName string `json:"isp_name,omitempty"`

	// Protocol is the protocol that was tested (e.g., "reality-vision", "xhttp").
	Protocol string `json:"protocol"`

	// Status is the observed status.
	Status ProtocolStatus `json:"status"`

	// Latency is the observed connection latency, if applicable.
	Latency time.Duration `json:"latency,omitempty"`

	// Timestamp is when the report was generated.
	Timestamp time.Time `json:"timestamp"`
}

// protocolEntry holds aggregated report data for a single protocol on a single ISP.
type protocolEntry struct {
	Reports []timedReport `json:"reports"`
}

// timedReport is a single report with its timestamp and status, used for aggregation.
type timedReport struct {
	Status    ProtocolStatus `json:"status"`
	Latency   time.Duration  `json:"latency,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// ISPEntry holds all protocol data for a single ISP.
type ISPEntry struct {
	ASNumber  uint32                    `json:"as_number"`
	ISPName   string                    `json:"isp_name,omitempty"`
	Protocols map[string]*protocolEntry `json:"protocols"`
}

// Recommendation is a protocol recommendation for a given ISP.
type Recommendation struct {
	Protocol string         `json:"protocol"`
	Status   ProtocolStatus `json:"status"`
	Score    float64        `json:"score"` // 0.0 (blocked) to 1.0 (fully working)
}

// BlockMap is a crowdsourced map of ISP-level protocol blocking status.
// It aggregates anonymous reports from clients and provides per-ISP
// protocol recommendations. Thread-safe for concurrent use.
type BlockMap struct {
	mu sync.RWMutex

	// ISPs maps AS number to ISP entry.
	ISPs map[uint32]*ISPEntry `json:"isps"`

	// DecayHalfLife controls how quickly old reports lose weight.
	// A report loses half its influence after this duration.
	DecayHalfLife time.Duration `json:"decay_half_life"`

	// MaxReportsPerProtocol limits stored reports per protocol per ISP.
	MaxReportsPerProtocol int `json:"max_reports_per_protocol"`

	// nowFunc is injectable for testing. Defaults to time.Now.
	nowFunc func() time.Time
}

// NewBlockMap creates a new blocking map with sensible defaults.
func NewBlockMap() *BlockMap {
	return &BlockMap{
		ISPs:                  make(map[uint32]*ISPEntry),
		DecayHalfLife:         24 * time.Hour,
		MaxReportsPerProtocol: 100,
		nowFunc:               time.Now,
	}
}

// AddReport adds a blocking report to the map. The report is anonymized:
// only AS number and protocol status are stored, never IP addresses.
func (bm *BlockMap) AddReport(report BlockReport) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	isp, ok := bm.ISPs[report.ASNumber]
	if !ok {
		isp = &ISPEntry{
			ASNumber:  report.ASNumber,
			ISPName:   report.ISPName,
			Protocols: make(map[string]*protocolEntry),
		}
		bm.ISPs[report.ASNumber] = isp
	}

	// Update ISP name if provided and not yet set.
	if report.ISPName != "" && isp.ISPName == "" {
		isp.ISPName = report.ISPName
	}

	entry, ok := isp.Protocols[report.Protocol]
	if !ok {
		entry = &protocolEntry{}
		isp.Protocols[report.Protocol] = entry
	}

	entry.Reports = append(entry.Reports, timedReport{
		Status:    report.Status,
		Latency:   report.Latency,
		Timestamp: report.Timestamp,
	})

	// Trim old reports if over limit.
	if bm.MaxReportsPerProtocol > 0 && len(entry.Reports) > bm.MaxReportsPerProtocol {
		excess := len(entry.Reports) - bm.MaxReportsPerProtocol
		entry.Reports = entry.Reports[excess:]
	}
}

// GetStatus returns the aggregated status of a protocol on a given ISP.
// It applies time-decay weighting so recent reports have more influence.
func (bm *BlockMap) GetStatus(asNumber uint32, protocol string) (ProtocolStatus, float64) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	isp, ok := bm.ISPs[asNumber]
	if !ok {
		return StatusUnknown, 0
	}

	entry, ok := isp.Protocols[protocol]
	if !ok {
		return StatusUnknown, 0
	}

	return bm.aggregateReports(entry.Reports)
}

// aggregateReports computes a weighted status from a set of timed reports.
// Returns the dominant status and a confidence score (0.0 to 1.0).
func (bm *BlockMap) aggregateReports(reports []timedReport) (ProtocolStatus, float64) {
	if len(reports) == 0 {
		return StatusUnknown, 0
	}

	now := bm.nowFunc()

	// Accumulate weighted votes for each status.
	votes := map[ProtocolStatus]float64{
		StatusWorking: 0,
		StatusSlow:    0,
		StatusBlocked: 0,
	}

	var totalWeight float64
	for _, r := range reports {
		w := bm.decayWeight(now, r.Timestamp)
		votes[r.Status] += w
		totalWeight += w
	}

	if totalWeight == 0 {
		return StatusUnknown, 0
	}

	// Find the dominant status.
	var best ProtocolStatus
	var bestWeight float64
	for status, weight := range votes {
		if weight > bestWeight {
			best = status
			bestWeight = weight
		}
	}

	confidence := bestWeight / totalWeight
	return best, confidence
}

// decayWeight calculates the exponential decay weight for a report.
// A report at time t has weight 2^(-(now-t)/halfLife).
func (bm *BlockMap) decayWeight(now, reportTime time.Time) float64 {
	if bm.DecayHalfLife <= 0 {
		return 1.0
	}
	age := now.Sub(reportTime)
	if age < 0 {
		age = 0
	}
	return math.Pow(2.0, -float64(age)/float64(bm.DecayHalfLife))
}

// Recommend returns ordered protocol recommendations for a given ISP.
// Protocols are sorted by score (higher = better). Blocked protocols
// appear last with low scores.
func (bm *BlockMap) Recommend(asNumber uint32) []Recommendation {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	isp, ok := bm.ISPs[asNumber]
	if !ok {
		return nil
	}

	var recs []Recommendation
	for proto, entry := range isp.Protocols {
		status, confidence := bm.aggregateReports(entry.Reports)
		score := bm.statusScore(status, confidence)
		recs = append(recs, Recommendation{
			Protocol: proto,
			Status:   status,
			Score:    score,
		})
	}

	// Sort by score descending.
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].Score > recs[j].Score
	})

	return recs
}

// statusScore converts a status and confidence into a numerical score.
func (bm *BlockMap) statusScore(status ProtocolStatus, confidence float64) float64 {
	var base float64
	switch status {
	case StatusWorking:
		base = 1.0
	case StatusSlow:
		base = 0.5
	case StatusBlocked:
		base = 0.0
	default:
		base = 0.3 // unknown gets a neutral-low score
	}
	// Scale by confidence: high confidence amplifies the base.
	// Low confidence pulls toward neutral (0.5).
	return base*confidence + 0.5*(1-confidence)
}

// ISPNames returns a map of AS number to ISP name for all known ISPs.
func (bm *BlockMap) ISPNames() map[uint32]string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	names := make(map[uint32]string, len(bm.ISPs))
	for asn, isp := range bm.ISPs {
		names[asn] = isp.ISPName
	}
	return names
}

// ReportCount returns the total number of reports stored.
func (bm *BlockMap) ReportCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	count := 0
	for _, isp := range bm.ISPs {
		for _, entry := range isp.Protocols {
			count += len(entry.Reports)
		}
	}
	return count
}

// Prune removes reports older than maxAge from all entries.
// Returns the number of reports removed.
func (bm *BlockMap) Prune(maxAge time.Duration) int {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	cutoff := bm.nowFunc().Add(-maxAge)
	removed := 0

	for _, isp := range bm.ISPs {
		for proto, entry := range isp.Protocols {
			var kept []timedReport
			for _, r := range entry.Reports {
				if r.Timestamp.After(cutoff) {
					kept = append(kept, r)
				} else {
					removed++
				}
			}
			entry.Reports = kept
			// Remove empty entries.
			if len(kept) == 0 {
				delete(isp.Protocols, proto)
			}
		}
	}

	return removed
}

// blockMapJSON is the serialization format for the blocking map.
type blockMapJSON struct {
	ISPs                  map[string]*ISPEntry `json:"isps"` // keyed by AS number string
	DecayHalfLifeSeconds  float64              `json:"decay_half_life_seconds"`
	MaxReportsPerProtocol int                  `json:"max_reports_per_protocol"`
}

// MarshalJSON serializes the blocking map to JSON.
func (bm *BlockMap) MarshalJSON() ([]byte, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	m := blockMapJSON{
		ISPs:                  make(map[string]*ISPEntry, len(bm.ISPs)),
		DecayHalfLifeSeconds:  bm.DecayHalfLife.Seconds(),
		MaxReportsPerProtocol: bm.MaxReportsPerProtocol,
	}

	for asn, isp := range bm.ISPs {
		key := json.Number(uintToString(asn))
		m.ISPs[string(key)] = isp
	}

	return json.Marshal(m)
}

// UnmarshalJSON deserializes the blocking map from JSON.
func (bm *BlockMap) UnmarshalJSON(data []byte) error {
	var m blockMapJSON
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.ISPs = make(map[uint32]*ISPEntry, len(m.ISPs))
	for key, isp := range m.ISPs {
		asn := stringToUint32(key)
		isp.ASNumber = asn
		bm.ISPs[asn] = isp
	}

	if m.DecayHalfLifeSeconds > 0 {
		bm.DecayHalfLife = time.Duration(m.DecayHalfLifeSeconds * float64(time.Second))
	}
	if m.MaxReportsPerProtocol > 0 {
		bm.MaxReportsPerProtocol = m.MaxReportsPerProtocol
	}
	if bm.nowFunc == nil {
		bm.nowFunc = time.Now
	}

	return nil
}

// ISPDetector determines the client's ISP from their AS number.
// In production this would use a GeoIP/ASN database; here we provide
// a lookup table that can be populated from external data.
type ISPDetector struct {
	mu      sync.RWMutex
	asNames map[uint32]string
}

// NewISPDetector creates a new ISP detector with an empty lookup table.
func NewISPDetector() *ISPDetector {
	return &ISPDetector{
		asNames: make(map[uint32]string),
	}
}

// Register adds an AS number to ISP name mapping.
func (d *ISPDetector) Register(asNumber uint32, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asNames[asNumber] = name
}

// RegisterBulk adds multiple mappings at once.
func (d *ISPDetector) RegisterBulk(mappings map[uint32]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for asn, name := range mappings {
		d.asNames[asn] = name
	}
}

// Lookup returns the ISP name for a given AS number.
// Returns empty string and false if not found.
func (d *ISPDetector) Lookup(asNumber uint32) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	name, ok := d.asNames[asNumber]
	return name, ok
}

// ASCount returns the number of registered AS entries.
func (d *ISPDetector) ASCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.asNames)
}

// helper to convert uint32 to string without importing strconv in a way
// that causes import cycle issues.
func uintToString(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func stringToUint32(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
