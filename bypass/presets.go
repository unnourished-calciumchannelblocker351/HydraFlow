package bypass

// Presets contains pre-built bypass configurations for common
// ISP/country scenarios. Each preset encodes the known DPI
// characteristics and the techniques that work against them.
//
// To use a preset, set BypassConfig.Preset to the map key.
// The engine merges preset values with any explicit user overrides.
var Presets = map[string]BypassConfig{

	// ---- Russia ----

	"russia-megafon": {
		FragmentEnabled:  true,
		FragmentSize:     "1-3",
		FragmentInterval: "1-3",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-200",
		SNIDomain:        "ya.ru",
		SNIFallbacks:     []string{"gosuslugi.ru", "sberbank.ru", "vk.com"},
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "xhttp-cdn", Priority: 2, Enabled: true},
			{Name: "reality", Priority: 3, Enabled: true},
		},
	},

	"russia-mts": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-300",
		SNIDomain:        "gosuslugi.ru",
		SNIFallbacks:     []string{"nalog.ru", "sberbank.ru", "ya.ru"},
		ChainEnabled:     true,
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "xhttp-cdn", Priority: 2, Enabled: true},
			{Name: "reality", Priority: 3, Enabled: true},
		},
	},

	"russia-beeline": {
		FragmentEnabled: false,
		PaddingEnabled:  false,
		SNIDomain:       "www.google.com",
		SNIFallbacks:    []string{"www.microsoft.com", "www.apple.com"},
		DOHEnabled:      true,
		DOHServer:       "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "hysteria2", Priority: 3, Enabled: true},
		},
	},

	"russia-rostelecom": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "2-5",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-200",
		SNIDomain:        "gosuslugi.ru",
		SNIFallbacks:     []string{"ya.ru", "nalog.ru", "kremlin.ru"},
		DesyncEnabled:    true,
		DesyncFakeTTL:    3,
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "xhttp-cdn", Priority: 2, Enabled: true},
			{Name: "reality", Priority: 3, Enabled: true},
		},
	},

	"russia-tele2": {
		FragmentEnabled:  true,
		FragmentSize:     "1-3",
		FragmentInterval: "1-3",
		FragmentPackets:  "tlshello",
		SNIDomain:        "vk.com",
		SNIFallbacks:     []string{"ya.ru", "sberbank.ru"},
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "hysteria2", Priority: 3, Enabled: true},
		},
	},

	// ---- China ----

	"china-telecom": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "5-20",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-300",
		SNIDomain:        "www.apple.com",
		SNIFallbacks:     []string{"www.microsoft.com", "www.samsung.com", "www.tesla.com"},
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "grpc-cdn", Priority: 2, Enabled: true},
			{Name: "reality", Priority: 3, Enabled: true},
		},
	},

	"china-unicom": {
		FragmentEnabled:  true,
		FragmentSize:     "2-10",
		FragmentInterval: "10-30",
		FragmentPackets:  "tlshello",
		SNIDomain:        "www.microsoft.com",
		SNIFallbacks:     []string{"www.apple.com", "www.oracle.com"},
		DesyncEnabled:    true,
		DesyncFakeTTL:    4,
		DOHEnabled:       true,
		DOHServer:        "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "shadowtls", Priority: 3, Enabled: true},
		},
	},

	"china-mobile": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "5-15",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "200-500",
		SNIDomain:        "www.apple.com",
		SNIFallbacks:     []string{"www.cisco.com", "www.intel.com"},
		DOHEnabled:       true,
		DOHServer:        "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "reality", Priority: 2, Enabled: true},
			{Name: "ss2022", Priority: 3, Enabled: true},
		},
	},

	// ---- Iran ----

	"iran-mci": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-300",
		SNIDomain:        "www.google.com",
		SNIFallbacks:     []string{"www.apple.com", "www.microsoft.com", "cloudflare.com"},
		DOHEnabled:       true,
		DOHServer:        "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "reality", Priority: 2, Enabled: true},
			{Name: "ss2022", Priority: 3, Enabled: true},
		},
	},

	"iran-irancell": {
		FragmentEnabled:  true,
		FragmentSize:     "2-10",
		FragmentInterval: "5-20",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-400",
		SNIDomain:        "www.microsoft.com",
		SNIFallbacks:     []string{"www.google.com", "www.apple.com"},
		DesyncEnabled:    true,
		DesyncFakeTTL:    3,
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "grpc-cdn", Priority: 2, Enabled: true},
			{Name: "reality", Priority: 3, Enabled: true},
		},
	},

	// ---- Turkey ----

	"turkey-turkcell": {
		FragmentEnabled: true,
		FragmentSize:    "5-20",
		FragmentPackets: "tlshello",
		SNIDomain:       "www.google.com",
		SNIFallbacks:    []string{"www.microsoft.com"},
		DOHEnabled:      true,
		DOHServer:       "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "hysteria2", Priority: 3, Enabled: true},
		},
	},

	// ---- UAE ----

	"uae-etisalat": {
		FragmentEnabled: false,
		PaddingEnabled:  true,
		PaddingSize:     "200-500",
		SNIDomain:       "www.microsoft.com",
		SNIFallbacks:    []string{"www.google.com", "www.apple.com"},
		DOHEnabled:      true,
		DOHServer:       "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "grpc-cdn", Priority: 2, Enabled: true},
			{Name: "hysteria2", Priority: 3, Enabled: true},
			{Name: "reality", Priority: 4, Enabled: true},
		},
	},

	// ---- Pakistan ----

	"pakistan-ptcl": {
		FragmentEnabled:  true,
		FragmentSize:     "5-50",
		FragmentInterval: "5-20",
		FragmentPackets:  "tlshello",
		SNIDomain:        "www.google.com",
		DOHEnabled:       true,
		DOHServer:        "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "reality", Priority: 2, Enabled: true},
			{Name: "ss2022", Priority: 3, Enabled: true},
		},
	},

	// ---- Uzbekistan ----

	"uzbekistan-uztelecom": {
		FragmentEnabled:  true,
		FragmentSize:     "1-5",
		FragmentInterval: "1-5",
		FragmentPackets:  "tlshello",
		SNIDomain:        "www.google.com",
		DOHEnabled:       true,
		DOHServer:        "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "hysteria2", Priority: 3, Enabled: true},
		},
	},

	// ---- Turkmenistan ----

	"turkmenistan": {
		FragmentEnabled:  true,
		FragmentSize:     "1-3",
		FragmentInterval: "1-3",
		FragmentPackets:  "tlshello",
		PaddingEnabled:   true,
		PaddingSize:      "100-500",
		DesyncEnabled:    true,
		DesyncFakeTTL:    2,
		ChainEnabled:     true,
		SNIDomain:        "www.google.com",
		DOHEnabled:       true,
		DOHServer:        "https://cloudflare-dns.com/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "ws-cdn", Priority: 1, Enabled: true},
			{Name: "xhttp-cdn", Priority: 2, Enabled: true},
		},
	},

	// ---- Default ----

	"default": {
		FragmentEnabled: false,
		PaddingEnabled:  false,
		DOHEnabled:      true,
		DOHServer:       "https://dns.google/dns-query",
		Protocols: []ProtocolConfig{
			{Name: "reality", Priority: 1, Enabled: true},
			{Name: "ws-cdn", Priority: 2, Enabled: true},
			{Name: "ss2022", Priority: 3, Enabled: true},
		},
	},
}

// PresetNames returns the sorted list of available preset names.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for name := range Presets {
		names = append(names, name)
	}
	// Simple sort.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return names
}

// GetPreset returns a copy of the named preset, or the default
// preset if the name is not found.
func GetPreset(name string) BypassConfig {
	preset, ok := Presets[name]
	if !ok {
		preset = Presets["default"]
	}
	// Return a copy to prevent mutation.
	return preset
}

// PresetForISP attempts to match an ISP name to a preset.
// It normalises the input (lowercase, trim) and checks for
// partial matches.
func PresetForISP(isp string) (BypassConfig, string) {
	// Normalise.
	lower := ""
	for _, c := range isp {
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		lower += string(c)
	}

	// Exact match.
	if preset, ok := Presets[lower]; ok {
		return preset, lower
	}

	// Partial match: check if the ISP name contains a known key.
	for name, preset := range Presets {
		if containsSubstring(lower, name) || containsSubstring(name, lower) {
			return preset, name
		}
	}

	return Presets["default"], "default"
}

// containsSubstring checks if haystack contains needle.
func containsSubstring(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
