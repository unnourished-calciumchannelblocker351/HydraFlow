package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/curve25519"
)

// ---- X25519 key pair generation (Reality) ----

// X25519KeyPair holds a Reality-compatible x25519 key pair.
type X25519KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// GenerateX25519Pair generates a new x25519 key pair for Reality protocol.
// The private key is clamped per the x25519 specification.
func GenerateX25519Pair() (*X25519KeyPair, error) {
	var privateKey [32]byte

	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}

	// Clamp private key per x25519 spec.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &X25519KeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil
}

// GenerateX25519PairHex generates a key pair with hex-encoded keys.
func GenerateX25519PairHex() (*X25519KeyPair, error) {
	var privateKey [32]byte

	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	return &X25519KeyPair{
		PrivateKey: hex.EncodeToString(privateKey[:]),
		PublicKey:  hex.EncodeToString(publicKey),
	}, nil
}

// ---- UUID generation ----

// GenerateUUID generates a cryptographically secure UUID v4.
func GenerateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}

	// Set version to 4.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant to RFC 4122.
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

// ---- Short ID generation ----

// GenerateShortID generates a random hex short ID for Reality.
// The length parameter specifies the number of hex characters (must be even).
func GenerateShortID(hexLen int) (string, error) {
	if hexLen <= 0 {
		hexLen = 8
	}
	if hexLen%2 != 0 {
		hexLen++
	}

	byteLen := hexLen / 2
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate short ID: %w", err)
	}

	return hex.EncodeToString(b), nil
}

// GenerateShortIDs generates multiple short IDs of varying lengths.
// This is useful for Reality configuration which accepts multiple short IDs.
func GenerateShortIDs(count int) ([]string, error) {
	ids := make([]string, 0, count)
	// Use different lengths: 2, 4, 8, 16 hex chars.
	lengths := []int{2, 4, 8, 8, 16}

	for i := 0; i < count; i++ {
		hexLen := lengths[i%len(lengths)]
		id, err := GenerateShortID(hexLen)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, nil
}

// ---- Key derivation ----

// DeriveKey derives a cryptographic key from a password and salt using Argon2id.
// Returns a 32-byte key.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

// DeriveKeyWithParams derives a key with custom Argon2id parameters.
func DeriveKeyWithParams(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// GenerateSalt generates a random salt of the specified length.
func GenerateSalt(length int) ([]byte, error) {
	if length <= 0 {
		length = 16
	}
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// ---- Secure random ----

// SecureRandom generates n cryptographically secure random bytes.
func SecureRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate secure random: %w", err)
	}
	return b, nil
}

// SecureRandomHex generates n random bytes and returns them as a hex string.
func SecureRandomHex(n int) (string, error) {
	b, err := SecureRandom(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---- Password hashing (bcrypt) ----

// HashPassword hashes a plaintext password using bcrypt with the default cost.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks a plaintext password against a bcrypt hash.
func VerifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---- JWT (HMAC-SHA256) ----

// JWTClaims holds standard JWT claims plus custom data.
type JWTClaims struct {
	Subject   string                 `json:"sub,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	ExpiresAt int64                  `json:"exp,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
	TokenID   string                 `json:"jti,omitempty"`
	Custom    map[string]interface{} `json:"custom,omitempty"`
}

// GenerateJWT creates a signed JWT token with HMAC-SHA256.
func GenerateJWT(claims JWTClaims, secret []byte) (string, error) {
	// Set defaults.
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()
	}
	if claims.TokenID == "" {
		jti, err := SecureRandomHex(16)
		if err != nil {
			return "", fmt.Errorf("generate jti: %w", err)
		}
		claims.TokenID = jti
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := hmacSHA256([]byte(signingInput), secret)

	return signingInput + "." + base64URLEncode(signature), nil
}

// ValidateJWT validates a JWT token and returns the claims if valid.
func ValidateJWT(tokenStr string, secret []byte) (*JWTClaims, error) {
	parts := splitJWT(tokenStr)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	expectedSig := hmacSHA256([]byte(signingInput), secret)
	actualSig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims.
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Check expiration.
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// ---- JWT helpers ----

func hmacSHA256(data, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func splitJWT(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	count := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
			count++
			if count >= 2 {
				break
			}
		}
	}
	if start <= len(token) {
		parts = append(parts, token[start:])
	}
	return parts
}
