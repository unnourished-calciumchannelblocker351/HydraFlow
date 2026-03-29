package blockmap

import (
	"math/rand"
	"time"
)

// GenerateSeedData creates realistic initial data based on known censorship
// patterns as of April 2026. This data is marked as "historical" and will
// be gradually replaced by real user reports.
func GenerateSeedData() []Report {
	var reports []Report

	// Russia — TSPU DPI actively blocks many protocols on major ISPs.
	ruISPs := []struct {
		name string
		asn  int
	}{
		{"MegaFon", 31213},
		{"MTS", 8359},
		{"Beeline", 3216},
		{"Tele2", 15378},
		{"Rostelecom", 12389},
		{"Dom.ru", 9049},
	}

	ruBlocking := map[string]map[string]string{
		"MegaFon": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "slow",
			"hysteria2":        "blocked",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"MTS": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "working",
			"hysteria2":        "blocked",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"Beeline": {
			"vless-reality":    "slow",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "working",
			"hysteria2":        "working",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"Tele2": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "slow",
			"hysteria2":        "blocked",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"Rostelecom": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "slow",
			"hysteria2":        "blocked",
			"shadowtls":        "slow",
			"chain-proxy":      "working",
		},
		"Dom.ru": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "working",
			"hysteria2":        "slow",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
	}

	for _, isp := range ruISPs {
		blocking := ruBlocking[isp.name]
		for proto, status := range blocking {
			reports = append(reports, generateReports("RU", isp.asn, isp.name, proto, status, 15)...)
		}
	}

	// China — Great Firewall, aggressive blocking.
	cnISPs := []struct {
		name string
		asn  int
	}{
		{"China Telecom", 4134},
		{"China Mobile", 9808},
		{"China Unicom", 4837},
	}

	cnBlocking := map[string]map[string]string{
		"China Telecom": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "slow",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "blocked",
			"shadowtls":        "slow",
			"chain-proxy":      "slow",
		},
		"China Mobile": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "slow",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "blocked",
			"shadowtls":        "blocked",
			"chain-proxy":      "slow",
		},
		"China Unicom": {
			"vless-reality":    "blocked",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "blocked",
			"shadowtls":        "slow",
			"chain-proxy":      "working",
		},
	}

	for _, isp := range cnISPs {
		blocking := cnBlocking[isp.name]
		for proto, status := range blocking {
			reports = append(reports, generateReports("CN", isp.asn, isp.name, proto, status, 12)...)
		}
	}

	// Iran — periodic shutdowns, mixed blocking.
	irISPs := []struct {
		name string
		asn  int
	}{
		{"MCI", 197207},
		{"Irancell", 44244},
		{"Rightel", 57218},
	}

	irBlocking := map[string]map[string]string{
		"MCI": {
			"vless-reality":    "working",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "slow",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"Irancell": {
			"vless-reality":    "working",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "blocked",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
		"Rightel": {
			"vless-reality":    "slow",
			"vless-ws-cdn":     "working",
			"shadowsocks-2022": "blocked",
			"hysteria2":        "slow",
			"shadowtls":        "working",
			"chain-proxy":      "working",
		},
	}

	for _, isp := range irISPs {
		blocking := irBlocking[isp.name]
		for proto, status := range blocking {
			reports = append(reports, generateReports("IR", isp.asn, isp.name, proto, status, 10)...)
		}
	}

	// Turkmenistan — one of the most restrictive.
	tmBlocking := map[string]string{
		"vless-reality":    "blocked",
		"vless-ws-cdn":     "slow",
		"shadowsocks-2022": "blocked",
		"hysteria2":        "blocked",
		"shadowtls":        "blocked",
		"chain-proxy":      "slow",
	}
	for proto, status := range tmBlocking {
		reports = append(reports, generateReports("TM", 20661, "Turkmentelecom", proto, status, 5)...)
	}

	// Kazakhstan — selective blocking.
	kzBlocking := map[string]string{
		"vless-reality":    "working",
		"vless-ws-cdn":     "working",
		"shadowsocks-2022": "working",
		"hysteria2":        "slow",
		"shadowtls":        "working",
		"chain-proxy":      "working",
	}
	for proto, status := range kzBlocking {
		reports = append(reports, generateReports("KZ", 9198, "Kazakhtelecom", proto, status, 6)...)
	}

	// Myanmar
	mmBlocking := map[string]string{
		"vless-reality":    "blocked",
		"vless-ws-cdn":     "working",
		"shadowsocks-2022": "slow",
		"hysteria2":        "blocked",
		"shadowtls":        "working",
		"chain-proxy":      "working",
	}
	for proto, status := range mmBlocking {
		reports = append(reports, generateReports("MM", 132167, "MPT", proto, status, 4)...)
	}

	// Pakistan — intermittent blocking.
	pkBlocking := map[string]string{
		"vless-reality":    "slow",
		"vless-ws-cdn":     "working",
		"shadowsocks-2022": "working",
		"hysteria2":        "slow",
		"shadowtls":        "working",
		"chain-proxy":      "working",
	}
	for proto, status := range pkBlocking {
		reports = append(reports, generateReports("PK", 9541, "PTCL", proto, status, 5)...)
	}

	return reports
}

// generateReports creates a set of realistic reports spread over the last
// few days, with some noise to simulate real usage patterns.
func generateReports(country string, asn int, isp, protocol, baseStatus string, count int) []Report {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(asn) + int64(len(protocol))))
	var reports []Report

	for i := 0; i < count; i++ {
		// Spread reports over last 5 days.
		hoursAgo := rng.Float64() * 120
		ts := time.Now().UTC().Add(-time.Duration(hoursAgo * float64(time.Hour)))

		status := baseStatus
		// Add noise: ~15% chance of different status.
		if rng.Float64() < 0.15 {
			switch baseStatus {
			case "working":
				status = "slow"
			case "blocked":
				if rng.Float64() < 0.5 {
					status = "slow"
				}
			case "slow":
				if rng.Float64() < 0.5 {
					status = "working"
				} else {
					status = "blocked"
				}
			}
		}

		latency := 0
		if status == "working" {
			latency = 50 + rng.Intn(200)
		} else if status == "slow" {
			latency = 500 + rng.Intn(2000)
		}

		reports = append(reports, Report{
			Country:    country,
			ASN:        asn,
			ISP:        isp,
			Protocol:   protocol,
			Status:     status,
			LatencyMs:  latency,
			Timestamp:  ts,
			Historical: true,
		})
	}

	return reports
}
