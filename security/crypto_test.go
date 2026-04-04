package security

import (
	"encoding/hex"
	"regexp"
	"testing"
	"time"
)

// ---- GenerateUUID tests ----

func TestGenerateUUID_ValidFormat(t *testing.T) {
	uuid, err := GenerateUUID()
	if err != nil {
		t.Fatalf("GenerateUUID: %v", err)
	}

	// UUID v4 format: 8-4-4-4-12 hex digits
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !re.MatchString(uuid) {
		t.Fatalf("UUID does not match v4 format: %s", uuid)
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		uuid, err := GenerateUUID()
		if err != nil {
			t.Fatalf("GenerateUUID: %v", err)
		}
		if seen[uuid] {
			t.Fatalf("duplicate UUID on iteration %d: %s", i, uuid)
		}
		seen[uuid] = true
	}
}

// ---- GenerateShortID tests ----

func TestGenerateShortID_CorrectLength(t *testing.T) {
	tests := []struct {
		name   string
		hexLen int
		want   int
	}{
		{"default (0 -> 8)", 0, 8},
		{"explicit 8", 8, 8},
		{"2 chars", 2, 2},
		{"16 chars", 16, 16},
		{"odd rounds up", 7, 8}, // 7 is odd, rounds to 8
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := GenerateShortID(tc.hexLen)
			if err != nil {
				t.Fatalf("GenerateShortID(%d): %v", tc.hexLen, err)
			}
			if len(id) != tc.want {
				t.Fatalf("expected len=%d, got len=%d (%s)", tc.want, len(id), id)
			}
			// Verify it's valid hex.
			if _, err := hex.DecodeString(id); err != nil {
				t.Fatalf("not valid hex: %s", id)
			}
		})
	}
}

// ---- Password hashing tests ----

func TestHashPassword_VerifyPassword_Roundtrip(t *testing.T) {
	password := "my-secret-password-123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !VerifyPassword(password, hash) {
		t.Fatal("VerifyPassword should succeed for correct password")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if VerifyPassword("wrong-password", hash) {
		t.Fatal("VerifyPassword should fail for wrong password")
	}
}

func TestHashPassword_DifferentHashesForSamePassword(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Fatal("bcrypt should produce different hashes (different salt) each time")
	}
}

// ---- DeriveKey tests ----

func TestDeriveKey_Deterministic(t *testing.T) {
	password := []byte("my-password")
	salt := []byte("fixed-salt-1234!")

	k1 := DeriveKey(password, salt)
	k2 := DeriveKey(password, salt)

	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}

	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatal("same input should produce same output")
		}
	}
}

func TestDeriveKey_DifferentInputDifferentOutput(t *testing.T) {
	salt := []byte("fixed-salt")
	k1 := DeriveKey([]byte("password-a"), salt)
	k2 := DeriveKey([]byte("password-b"), salt)

	same := true
	for i := range k1 {
		if k1[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestDeriveKey_DifferentSaltDifferentOutput(t *testing.T) {
	password := []byte("same-password")
	k1 := DeriveKey(password, []byte("salt-A"))
	k2 := DeriveKey(password, []byte("salt-B"))

	same := true
	for i := range k1 {
		if k1[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different salts should produce different keys")
	}
}

// ---- JWT tests ----

func TestGenerateJWT_ValidateJWT_Roundtrip(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt")

	claims := JWTClaims{
		Subject:   "user-42",
		Issuer:    "hydraflow",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Custom: map[string]interface{}{
			"role": "admin",
		},
	}

	token, err := GenerateJWT(claims, secret)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	parsed, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT: %v", err)
	}

	if parsed.Subject != "user-42" {
		t.Fatalf("expected subject 'user-42', got %q", parsed.Subject)
	}
	if parsed.Issuer != "hydraflow" {
		t.Fatalf("expected issuer 'hydraflow', got %q", parsed.Issuer)
	}
}

func TestValidateJWT_ExpiredTokenRejected(t *testing.T) {
	secret := []byte("test-secret")

	claims := JWTClaims{
		Subject:   "user",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // expired 1 hour ago
		TokenID:   "static-jti",
	}

	token, err := GenerateJWT(claims, secret)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Error() != "token expired" {
		t.Fatalf("expected 'token expired' error, got: %v", err)
	}
}

func TestValidateJWT_WrongSecretRejected(t *testing.T) {
	claims := JWTClaims{
		Subject:   "user",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		TokenID:   "static-jti",
	}

	token, err := GenerateJWT(claims, []byte("secret-1"))
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	_, err = ValidateJWT(token, []byte("secret-2"))
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestValidateJWT_MalformedToken(t *testing.T) {
	_, err := ValidateJWT("not-a-jwt", []byte("secret"))
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

// ---- SecureRandom tests ----

func TestSecureRandom_CorrectLength(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64} {
		b, err := SecureRandom(n)
		if err != nil {
			t.Fatalf("SecureRandom(%d): %v", n, err)
		}
		if len(b) != n {
			t.Fatalf("expected %d bytes, got %d", n, len(b))
		}
	}
}

func TestSecureRandom_DifferentEachCall(t *testing.T) {
	b1, _ := SecureRandom(32)
	b2, _ := SecureRandom(32)

	same := true
	for i := range b1 {
		if b1[i] != b2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two calls to SecureRandom should produce different bytes")
	}
}

func TestSecureRandomHex_CorrectLength(t *testing.T) {
	h, err := SecureRandomHex(16)
	if err != nil {
		t.Fatalf("SecureRandomHex: %v", err)
	}
	// 16 bytes -> 32 hex chars
	if len(h) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%s)", len(h), h)
	}
	if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("not valid hex: %s", h)
	}
}

// ---- X25519 key pair tests ----

func TestGenerateX25519Pair_ValidKeyLengths(t *testing.T) {
	kp, err := GenerateX25519Pair()
	if err != nil {
		t.Fatalf("GenerateX25519Pair: %v", err)
	}
	if kp.PrivateKey == "" || kp.PublicKey == "" {
		t.Fatal("keys should not be empty")
	}
	// base64url encoded 32 bytes = 43 chars (no padding)
	if len(kp.PrivateKey) != 43 || len(kp.PublicKey) != 43 {
		t.Fatalf("expected 43-char base64url keys, got priv=%d pub=%d",
			len(kp.PrivateKey), len(kp.PublicKey))
	}
}

func TestGenerateX25519PairHex_ValidKeyLengths(t *testing.T) {
	kp, err := GenerateX25519PairHex()
	if err != nil {
		t.Fatalf("GenerateX25519PairHex: %v", err)
	}
	// hex-encoded 32 bytes = 64 hex chars
	if len(kp.PrivateKey) != 64 || len(kp.PublicKey) != 64 {
		t.Fatalf("expected 64-char hex keys, got priv=%d pub=%d",
			len(kp.PrivateKey), len(kp.PublicKey))
	}
}

func TestGenerateX25519Pair_UniqueEachCall(t *testing.T) {
	kp1, _ := GenerateX25519Pair()
	kp2, _ := GenerateX25519Pair()
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Fatal("two generated key pairs should differ")
	}
}

// ---- GenerateShortIDs tests ----

func TestGenerateShortIDs_Count(t *testing.T) {
	ids, err := GenerateShortIDs(5)
	if err != nil {
		t.Fatalf("GenerateShortIDs: %v", err)
	}
	if len(ids) != 5 {
		t.Fatalf("expected 5 IDs, got %d", len(ids))
	}
	// Verify each is valid hex.
	for i, id := range ids {
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("ID[%d] not valid hex: %s", i, id)
		}
	}
}

// ---- GenerateSalt tests ----

func TestGenerateSalt_CorrectLength(t *testing.T) {
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(salt))
	}
}

func TestGenerateSalt_DefaultLength(t *testing.T) {
	salt, err := GenerateSalt(0)
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("expected default 16 bytes, got %d", len(salt))
	}
}
