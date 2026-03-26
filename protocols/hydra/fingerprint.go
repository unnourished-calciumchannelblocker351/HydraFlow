package hydra

import (
	"crypto/tls"
	"math/rand"
	"sync"
)

// FingerprintProfile defines a TLS client fingerprint that mimics a
// specific real browser. Each profile specifies cipher suites, TLS
// extensions, elliptic curves, signature algorithms, and ALPN protocols
// that match the browser's actual TLS implementation.
type FingerprintProfile struct {
	// Name identifies the browser and version being mimicked.
	Name string

	// CipherSuites is the ordered list of cipher suites to offer.
	CipherSuites []uint16

	// CurvePreferences defines the elliptic curves to advertise.
	CurvePreferences []tls.CurveID

	// SignatureAlgorithms lists the signature algorithms to offer.
	// Stored as uint16 to accommodate all algorithm types.
	SignatureAlgorithms []uint16

	// ALPNProtocols lists the ALPN protocols to advertise.
	ALPNProtocols []string

	// MinVersion is the minimum TLS version the profile supports.
	MinVersion uint16

	// MaxVersion is the maximum TLS version the profile supports.
	MaxVersion uint16

	// ServerName is the SNI value (set at runtime, not part of the profile).
	ServerName string
}

// FingerprintPool holds a collection of browser fingerprint profiles
// and provides thread-safe random selection with slight variations
// to produce different JA3/JA4 hashes on each call.
type FingerprintPool struct {
	mu       sync.RWMutex
	profiles []FingerprintProfile
}

// NewFingerprintPool creates a pool pre-loaded with realistic browser profiles.
func NewFingerprintPool() *FingerprintPool {
	pool := &FingerprintPool{}
	pool.profiles = builtinProfiles()
	return pool
}

// RandomFingerprint selects a random profile from the pool and applies
// slight variations (shuffling optional cipher suites, varying ALPN
// order) to produce a unique JA3/JA4 fingerprint each time.
func (fp *FingerprintPool) RandomFingerprint() FingerprintProfile {
	fp.mu.RLock()
	profiles := fp.profiles
	fp.mu.RUnlock()

	if len(profiles) == 0 {
		return defaultProfile()
	}

	// Pick a random base profile.
	base := profiles[rand.Intn(len(profiles))]

	// Apply variations to make the fingerprint unique.
	varied := FingerprintProfile{
		Name:       base.Name,
		MinVersion: base.MinVersion,
		MaxVersion: base.MaxVersion,
	}

	// Copy and slightly vary cipher suites — shuffle the tail portion
	// (after the first 3 mandatory suites) to change the JA3 hash
	// while keeping the most important suites prioritized.
	varied.CipherSuites = make([]uint16, len(base.CipherSuites))
	copy(varied.CipherSuites, base.CipherSuites)
	if len(varied.CipherSuites) > 3 {
		tail := varied.CipherSuites[3:]
		rand.Shuffle(len(tail), func(i, j int) {
			tail[i], tail[j] = tail[j], tail[i]
		})
	}

	// Copy curve preferences with occasional reordering.
	varied.CurvePreferences = make([]tls.CurveID, len(base.CurvePreferences))
	copy(varied.CurvePreferences, base.CurvePreferences)
	if len(varied.CurvePreferences) > 1 && rand.Intn(3) == 0 {
		// Swap two random curves ~33% of the time.
		i := rand.Intn(len(varied.CurvePreferences))
		j := rand.Intn(len(varied.CurvePreferences))
		varied.CurvePreferences[i], varied.CurvePreferences[j] =
			varied.CurvePreferences[j], varied.CurvePreferences[i]
	}

	// Copy signature algorithms, occasionally dropping one optional entry.
	varied.SignatureAlgorithms = make([]uint16, len(base.SignatureAlgorithms))
	copy(varied.SignatureAlgorithms, base.SignatureAlgorithms)
	if len(varied.SignatureAlgorithms) > 4 && rand.Intn(4) == 0 {
		// Drop the last sig alg ~25% of the time.
		varied.SignatureAlgorithms = varied.SignatureAlgorithms[:len(varied.SignatureAlgorithms)-1]
	}

	// Copy ALPN — some browsers send h2 first, others http/1.1 first.
	varied.ALPNProtocols = make([]string, len(base.ALPNProtocols))
	copy(varied.ALPNProtocols, base.ALPNProtocols)

	return varied
}

// AddProfile adds a custom fingerprint profile to the pool.
func (fp *FingerprintPool) AddProfile(p FingerprintProfile) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.profiles = append(fp.profiles, p)
}

// Profiles returns a copy of all profiles in the pool.
func (fp *FingerprintPool) Profiles() []FingerprintProfile {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	result := make([]FingerprintProfile, len(fp.profiles))
	copy(result, fp.profiles)
	return result
}

// ToTLSConfig converts a FingerprintProfile to a *tls.Config suitable
// for establishing a TLS connection that mimics the profiled browser.
func (p *FingerprintProfile) ToTLSConfig(serverName string) *tls.Config {
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         p.MinVersion,
		MaxVersion:         p.MaxVersion,
		CipherSuites:       p.CipherSuites,
		CurvePreferences:   p.CurvePreferences,
		NextProtos:         p.ALPNProtocols,
	}
	return cfg
}

// builtinProfiles returns realistic browser TLS fingerprint profiles.
// These are modeled after actual browser implementations to make
// connections indistinguishable from legitimate browser traffic.
func builtinProfiles() []FingerprintProfile {
	return []FingerprintProfile{
		chromeProfile(),
		chrome120Profile(),
		firefoxProfile(),
		firefox121Profile(),
		safariProfile(),
		edgeProfile(),
	}
}

func chromeProfile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Chrome/119",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SignatureAlgorithms: []uint16{
			0x0403, // ECDSA-SECP256R1-SHA256
			0x0804, // RSA-PSS-RSAE-SHA256
			0x0401, // RSA-PKCS1-SHA256
			0x0503, // ECDSA-SECP384R1-SHA384
			0x0805, // RSA-PSS-RSAE-SHA384
			0x0501, // RSA-PKCS1-SHA384
			0x0806, // RSA-PSS-RSAE-SHA512
			0x0601, // RSA-PKCS1-SHA512
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

func chrome120Profile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Chrome/120",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0804, 0x0401, 0x0503,
			0x0805, 0x0501, 0x0806, 0x0601,
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

func firefoxProfile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Firefox/120",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0503, 0x0603, // ECDSA variants
			0x0804, 0x0805, 0x0806, // RSA-PSS variants
			0x0401, 0x0501, 0x0601, // RSA-PKCS1 variants
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

func firefox121Profile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Firefox/121",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0503, 0x0804, 0x0805,
			0x0401, 0x0501, 0x0601,
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

func safariProfile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Safari/17",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0503, 0x0603,
			0x0804, 0x0805, 0x0806,
			0x0401, 0x0501, 0x0601,
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

func edgeProfile() FingerprintProfile {
	return FingerprintProfile{
		Name: "Edge/119",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0804, 0x0401, 0x0503,
			0x0805, 0x0501, 0x0806, 0x0601,
		},
		ALPNProtocols: []string{"h2", "http/1.1"},
		MinVersion:    tls.VersionTLS12,
		MaxVersion:    tls.VersionTLS13,
	}
}

// defaultProfile returns a safe fallback profile if the pool is empty.
func defaultProfile() FingerprintProfile {
	return chromeProfile()
}
