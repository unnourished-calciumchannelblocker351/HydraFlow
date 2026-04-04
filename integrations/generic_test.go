package integrations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewGenericProvider_RequiresAPIURL(t *testing.T) {
	_, err := NewGenericProvider(GenericConfig{
		UsersEndpoint: "/api/users",
	})
	if err == nil {
		t.Fatal("expected error when api_url is empty")
	}
}

func TestNewGenericProvider_RequiresUsersEndpoint(t *testing.T) {
	_, err := NewGenericProvider(GenericConfig{
		APIURL: "http://localhost:8080",
	})
	if err == nil {
		t.Fatal("expected error when users_endpoint is empty")
	}
}

func TestNewGenericProvider_Success(t *testing.T) {
	p, err := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost:8080",
		UsersEndpoint: "/api/users",
		ServerIP:      "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestNewGenericProvider_AppliesDefaults(t *testing.T) {
	p, err := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost:8080",
		UsersEndpoint: "/api/users",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.cfg.AuthHeader != "Authorization" {
		t.Fatalf("expected default AuthHeader 'Authorization', got %q", p.cfg.AuthHeader)
	}
	if p.cfg.AuthPrefix != "Bearer " {
		t.Fatalf("expected default AuthPrefix 'Bearer ', got %q", p.cfg.AuthPrefix)
	}
	if p.cfg.FieldUUID != "uuid" {
		t.Fatalf("expected default FieldUUID 'uuid', got %q", p.cfg.FieldUUID)
	}
	if p.cfg.StatusActive != "active" {
		t.Fatalf("expected default StatusActive 'active', got %q", p.cfg.StatusActive)
	}
}

func TestNavigateJSON(t *testing.T) {
	root := map[string]interface{}{
		"data": map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{"name": "alice"},
			},
		},
	}

	result := navigateJSON(root, "data.users")
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatal("expected array type")
	}
	if len(arr) != 1 {
		t.Fatalf("expected 1 element, got %d", len(arr))
	}
}

func TestNavigateJSON_MissingPath(t *testing.T) {
	root := map[string]interface{}{
		"data": map[string]interface{}{},
	}

	result := navigateJSON(root, "data.nonexistent")
	if result != nil {
		t.Fatalf("expected nil for missing path, got %v", result)
	}
}

func TestNavigateJSON_EmptyPath(t *testing.T) {
	root := map[string]interface{}{
		"key": "value",
	}

	result := navigateJSON(root, "")
	// Empty path returns the root itself.
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map type for empty path")
	}
	if m["key"] != "value" {
		t.Fatalf("expected 'value', got %v", m["key"])
	}
}

func TestGenericProvider_ExtractList_RootArray(t *testing.T) {
	p := &GenericProvider{}

	body := `[{"uuid":"uuid-1","email":"alice"},{"uuid":"uuid-2","email":"bob"}]`
	items, err := p.extractList([]byte(body), "")
	if err != nil {
		t.Fatalf("extract list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestGenericProvider_ExtractList_NestedPath(t *testing.T) {
	p := &GenericProvider{}

	body := `{"data":{"users":[{"uuid":"uuid-1"},{"uuid":"uuid-2"}]}}`
	items, err := p.extractList([]byte(body), "data.users")
	if err != nil {
		t.Fatalf("extract list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
}

func TestGenericProvider_ExtractList_InvalidPath(t *testing.T) {
	p := &GenericProvider{}

	body := `{"data":{}}`
	_, err := p.extractList([]byte(body), "data.missing")
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestGenericProvider_UserToNode_Active(t *testing.T) {
	p, _ := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})

	user := map[string]interface{}{
		"uuid":   "test-uuid",
		"email":  "alice@example.com",
		"status": "active",
		"port":   float64(443),
	}

	node, ok := p.userToNode(user)
	if !ok {
		t.Fatal("expected user to be accepted")
	}
	if node.UUID != "test-uuid" {
		t.Fatalf("expected uuid 'test-uuid', got %q", node.UUID)
	}
	if node.Email != "alice@example.com" {
		t.Fatalf("expected email 'alice@example.com', got %q", node.Email)
	}
	if node.Port != 443 {
		t.Fatalf("expected port 443, got %d", node.Port)
	}
	if node.ServerName != "generic" {
		t.Fatalf("expected serverName 'generic', got %q", node.ServerName)
	}
}

func TestGenericProvider_UserToNode_Inactive(t *testing.T) {
	p, _ := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})

	user := map[string]interface{}{
		"uuid":   "test-uuid",
		"email":  "alice@example.com",
		"status": "disabled",
	}

	_, ok := p.userToNode(user)
	if ok {
		t.Fatal("expected disabled user to be skipped")
	}
}

func TestGenericProvider_UserToNode_Expired(t *testing.T) {
	p, _ := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})

	user := map[string]interface{}{
		"uuid":      "test-uuid",
		"email":     "alice@example.com",
		"status":    "active",
		"expire_at": float64(1000000), // very old timestamp
	}

	_, ok := p.userToNode(user)
	if ok {
		t.Fatal("expected expired user to be skipped")
	}
}

func TestGenericProvider_UserToNode_EnabledField(t *testing.T) {
	p, _ := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
		FieldStatus:   "",       // clear status field
		FieldEnabled:  "active", // use boolean field instead
	})

	user := map[string]interface{}{
		"uuid":   "test-uuid",
		"email":  "alice@example.com",
		"active": true,
	}

	_, ok := p.userToNode(user)
	if !ok {
		t.Fatal("expected enabled user to be accepted")
	}

	userOff := map[string]interface{}{
		"uuid":   "test-uuid",
		"email":  "alice@example.com",
		"active": false,
	}

	_, ok = p.userToNode(userOff)
	if ok {
		t.Fatal("expected disabled user to be skipped")
	}
}

func TestGenericProvider_UserToNode_FallbackToUsername(t *testing.T) {
	p, _ := NewGenericProvider(GenericConfig{
		APIURL:        "http://localhost",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})

	user := map[string]interface{}{
		"uuid":     "test-uuid",
		"username": "bob",
		"status":   "active",
	}

	node, ok := p.userToNode(user)
	if !ok {
		t.Fatal("expected user to be accepted")
	}
	if node.Email != "bob" {
		t.Fatalf("expected email to fall back to username 'bob', got %q", node.Email)
	}
}

func TestGenericProvider_FetchUsersHTTP(t *testing.T) {
	users := []map[string]interface{}{
		{"uuid": "uuid-1", "email": "alice", "status": "active"},
		{"uuid": "uuid-2", "email": "bob", "status": "active"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(users)
	}))
	defer srv.Close()

	p, err := NewGenericProvider(GenericConfig{
		APIURL:        srv.URL,
		APIToken:      "test-token",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 users, got %d", len(result))
	}
}

func TestGenericProvider_FetchUsersHTTP_NestedResponse(t *testing.T) {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"items": []interface{}{
				map[string]interface{}{"uuid": "uuid-1", "email": "alice"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, err := NewGenericProvider(GenericConfig{
		APIURL:        srv.URL,
		UsersEndpoint: "/api/users",
		UsersListPath: "data.items",
		ServerIP:      "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 user, got %d", len(result))
	}
}

func TestGenericProvider_CustomAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "Token my-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"uuid": "uuid-1", "email": "alice"},
		})
	}))
	defer srv.Close()

	p, err := NewGenericProvider(GenericConfig{
		APIURL:        srv.URL,
		APIToken:      "my-key",
		AuthHeader:    "X-API-Key",
		AuthPrefix:    "Token ",
		UsersEndpoint: "/api/users",
		ServerIP:      "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	result, err := p.fetchUsers()
	if err != nil {
		t.Fatalf("fetch users: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 user, got %d", len(result))
	}
}

// --- JSON field helper tests ---

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"str":   "hello",
		"num":   float64(42),
		"empty": nil,
	}

	if getString(m, "str") != "hello" {
		t.Fatal("expected 'hello'")
	}
	if getString(m, "num") != "42" {
		t.Fatalf("expected '42', got %q", getString(m, "num"))
	}
	if getString(m, "empty") != "" {
		t.Fatal("expected empty string for nil")
	}
	if getString(m, "missing") != "" {
		t.Fatal("expected empty string for missing key")
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{
		"num":    float64(42),
		"str":    "100",
		"empty":  nil,
	}

	if getInt(m, "num") != 42 {
		t.Fatalf("expected 42, got %d", getInt(m, "num"))
	}
	if getInt(m, "str") != 100 {
		t.Fatalf("expected 100, got %d", getInt(m, "str"))
	}
	if getInt(m, "empty") != 0 {
		t.Fatalf("expected 0, got %d", getInt(m, "empty"))
	}
	if getInt(m, "missing") != 0 {
		t.Fatalf("expected 0, got %d", getInt(m, "missing"))
	}
}

func TestGetBool(t *testing.T) {
	m := map[string]interface{}{
		"bool_true":  true,
		"bool_false": false,
		"str_true":   "true",
		"str_1":      "1",
		"num_1":      float64(1),
		"num_0":      float64(0),
		"empty":      nil,
	}

	if !getBool(m, "bool_true") {
		t.Fatal("expected true for bool_true")
	}
	if getBool(m, "bool_false") {
		t.Fatal("expected false for bool_false")
	}
	if !getBool(m, "str_true") {
		t.Fatal("expected true for str_true")
	}
	if !getBool(m, "str_1") {
		t.Fatal("expected true for str_1")
	}
	if !getBool(m, "num_1") {
		t.Fatal("expected true for num_1")
	}
	if getBool(m, "num_0") {
		t.Fatal("expected false for num_0")
	}
	if getBool(m, "empty") {
		t.Fatal("expected false for nil")
	}
}

func TestGetInt64(t *testing.T) {
	m := map[string]interface{}{
		"num":  float64(1234567890),
		"str":  "9876543210",
		"zero": float64(0),
	}

	if getInt64(m, "num") != 1234567890 {
		t.Fatalf("expected 1234567890, got %d", getInt64(m, "num"))
	}
	if getInt64(m, "str") != 9876543210 {
		t.Fatalf("expected 9876543210, got %d", getInt64(m, "str"))
	}
	if getInt64(m, "zero") != 0 {
		t.Fatalf("expected 0, got %d", getInt64(m, "zero"))
	}
	if getInt64(m, "missing") != 0 {
		t.Fatalf("expected 0 for missing, got %d", getInt64(m, "missing"))
	}
}
