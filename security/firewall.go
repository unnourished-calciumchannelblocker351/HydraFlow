package security

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"
)

// FirewallConfig configures server-side firewall protection.
type FirewallConfig struct {
	// AllowedCountries is a list of country codes to allow (whitelist mode).
	// If non-empty, only these countries are allowed; all others are blocked.
	AllowedCountries []string

	// BlockedCountries is a list of country codes to block (blacklist mode).
	// Only used if AllowedCountries is empty.
	BlockedCountries []string

	// PortKnockingEnabled enables port knocking for admin access.
	PortKnockingEnabled bool

	// PortKnockingSequence is the sequence of ports to knock.
	PortKnockingSequence []int

	// PortKnockingTimeout is the max time (seconds) to complete the knock sequence.
	PortKnockingTimeout int
}

// Firewall manages iptables rules for the proxy server.
type Firewall struct {
	mu     sync.Mutex
	config FirewallConfig
	logger *slog.Logger

	// blockedIPs tracks dynamically blocked IPs.
	blockedIPs map[string]bool
}

// NewFirewall creates a new Firewall manager.
func NewFirewall(config FirewallConfig, logger *slog.Logger) *Firewall {
	if logger == nil {
		logger = slog.Default()
	}
	return &Firewall{
		config:     config,
		logger:     logger,
		blockedIPs: make(map[string]bool),
	}
}

// SetupIPTables configures iptables rules for the given proxy ports.
// It creates a dedicated chain for HydraFlow rules.
func (fw *Firewall) SetupIPTables(ports []int) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.iptablesAvailable() {
		return fmt.Errorf("iptables not available")
	}

	chainName := "HYDRAFLOW"

	// Create the chain (ignore error if it already exists).
	runIPTables("-N", chainName)

	// Flush existing rules in the chain.
	if err := runIPTables("-F", chainName); err != nil {
		return fmt.Errorf("flush chain: %w", err)
	}

	// Allow established connections.
	if err := runIPTables("-A", chainName,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT"); err != nil {
		fw.logger.Warn("could not add conntrack rule", "error", err)
	}

	// Allow loopback.
	if err := runIPTables("-A", chainName,
		"-i", "lo", "-j", "ACCEPT"); err != nil {
		fw.logger.Warn("could not add loopback rule", "error", err)
	}

	// Allow specified ports.
	for _, port := range ports {
		portStr := fmt.Sprintf("%d", port)

		// TCP.
		if err := runIPTables("-A", chainName,
			"-p", "tcp", "--dport", portStr,
			"-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow tcp port %d: %w", port, err)
		}

		// UDP.
		if err := runIPTables("-A", chainName,
			"-p", "udp", "--dport", portStr,
			"-j", "ACCEPT"); err != nil {
			return fmt.Errorf("allow udp port %d: %w", port, err)
		}
	}

	// Rate limiting: limit new connections per IP.
	if err := runIPTables("-A", chainName,
		"-p", "tcp", "--syn",
		"-m", "connlimit", "--connlimit-above", "50",
		"-j", "DROP"); err != nil {
		fw.logger.Warn("could not add connlimit rule (module may not be available)", "error", err)
	}

	// Add the chain to INPUT if not already present.
	if err := runIPTables("-C", "INPUT", "-j", chainName); err != nil {
		if err := runIPTables("-I", "INPUT", "1", "-j", chainName); err != nil {
			return fmt.Errorf("insert chain into INPUT: %w", err)
		}
	}

	fw.logger.Info("iptables rules configured",
		"chain", chainName,
		"ports", ports,
	)

	return nil
}

// BlockIP adds a DROP rule for a specific IP address.
func (fw *Firewall) BlockIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if fw.blockedIPs[ip] {
		return nil // already blocked
	}

	if fw.iptablesAvailable() {
		if err := runIPTables("-I", "HYDRAFLOW", "1",
			"-s", ip, "-j", "DROP"); err != nil {
			return fmt.Errorf("block IP %s: %w", ip, err)
		}
	}

	fw.blockedIPs[ip] = true
	fw.logger.Info("IP blocked", "ip", ip)
	return nil
}

// UnblockIP removes the DROP rule for a specific IP address.
func (fw *Firewall) UnblockIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	if !fw.blockedIPs[ip] {
		return nil // not blocked
	}

	if fw.iptablesAvailable() {
		if err := runIPTables("-D", "HYDRAFLOW",
			"-s", ip, "-j", "DROP"); err != nil {
			fw.logger.Warn("could not remove iptables rule", "ip", ip, "error", err)
		}
	}

	delete(fw.blockedIPs, ip)
	fw.logger.Info("IP unblocked", "ip", ip)
	return nil
}

// IsBlocked checks if an IP is currently blocked.
func (fw *Firewall) IsBlocked(ip string) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.blockedIPs[ip]
}

// BlockedIPs returns a list of all currently blocked IPs.
func (fw *Firewall) BlockedIPs() []string {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	ips := make([]string, 0, len(fw.blockedIPs))
	for ip := range fw.blockedIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GeoBlock configures country-based blocking using iptables geoip module.
// Requires xt_geoip kernel module and MaxMind GeoIP database.
func (fw *Firewall) GeoBlock(countries []string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if len(countries) == 0 {
		return nil
	}

	if !fw.iptablesAvailable() {
		return fmt.Errorf("iptables not available")
	}

	// Build comma-separated country list.
	countryList := ""
	for i, c := range countries {
		if i > 0 {
			countryList += ","
		}
		countryList += c
	}

	// Try xt_geoip first.
	err := runIPTables("-A", "HYDRAFLOW",
		"-m", "geoip", "--src-cc", countryList,
		"-j", "DROP")
	if err != nil {
		fw.logger.Warn("xt_geoip module not available, geo-blocking requires manual setup",
			"error", err,
			"countries", countries,
		)
		return fmt.Errorf("geoip module not available: %w", err)
	}

	fw.logger.Info("geo-blocking configured", "countries", countries)
	return nil
}

// GeoAllow configures country-based allowlisting. Only traffic from the
// specified countries is accepted; all other countries are dropped.
func (fw *Firewall) GeoAllow(countries []string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if len(countries) == 0 {
		return nil
	}

	if !fw.iptablesAvailable() {
		return fmt.Errorf("iptables not available")
	}

	countryList := ""
	for i, c := range countries {
		if i > 0 {
			countryList += ","
		}
		countryList += c
	}

	// Allow specified countries.
	err := runIPTables("-A", "HYDRAFLOW",
		"-m", "geoip", "--src-cc", countryList,
		"-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("geoip allow: %w", err)
	}

	// Drop everything else (add at end of chain).
	err = runIPTables("-A", "HYDRAFLOW", "-j", "DROP")
	if err != nil {
		return fmt.Errorf("add default drop: %w", err)
	}

	fw.logger.Info("geo-allowlisting configured", "countries", countries)
	return nil
}

// Cleanup removes all HydraFlow iptables rules.
func (fw *Firewall) Cleanup() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.iptablesAvailable() {
		return nil
	}

	chainName := "HYDRAFLOW"

	// Remove reference from INPUT.
	runIPTables("-D", "INPUT", "-j", chainName)

	// Flush and delete the chain.
	runIPTables("-F", chainName)
	runIPTables("-X", chainName)

	fw.blockedIPs = make(map[string]bool)
	fw.logger.Info("iptables rules cleaned up")
	return nil
}

// ---- Port Knocking ----

// PortKnocking implements a port knocking mechanism for securing admin access.
type PortKnocking struct {
	mu       sync.Mutex
	sequence []int
	timeout  int // seconds
	states   map[string]*knockState
	logger   *slog.Logger
}

type knockState struct {
	position  int
	lastKnock int64 // unix timestamp
}

// NewPortKnocking creates a port knocking handler.
func NewPortKnocking(sequence []int, timeoutSec int, logger *slog.Logger) *PortKnocking {
	if logger == nil {
		logger = slog.Default()
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &PortKnocking{
		sequence: sequence,
		timeout:  timeoutSec,
		states:   make(map[string]*knockState),
		logger:   logger,
	}
}

// RecordKnock records a port knock from an IP. Returns true if the
// full sequence is complete and the IP should be granted access.
func (pk *PortKnocking) RecordKnock(ip string, port int) bool {
	pk.mu.Lock()
	defer pk.mu.Unlock()

	if len(pk.sequence) == 0 {
		return true
	}

	now := unixNow()
	state, exists := pk.states[ip]

	if !exists {
		state = &knockState{}
		pk.states[ip] = state
	}

	// Check timeout.
	if state.lastKnock > 0 && (now-state.lastKnock) > int64(pk.timeout) {
		// Reset on timeout.
		state.position = 0
	}

	// Check if this port matches the expected next in sequence.
	if state.position < len(pk.sequence) && port == pk.sequence[state.position] {
		state.position++
		state.lastKnock = now

		if state.position >= len(pk.sequence) {
			// Sequence complete.
			delete(pk.states, ip)
			pk.logger.Info("port knocking sequence completed", "ip_hash", hashIPForLog(ip))
			return true
		}
	} else {
		// Wrong port, reset.
		state.position = 0
		state.lastKnock = 0
	}

	return false
}

// ---- Helpers ----

func (fw *Firewall) iptablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	return cmd.Run()
}

// unixNow returns the current Unix timestamp.
func unixNow() int64 {
	return time.Now().Unix()
}
