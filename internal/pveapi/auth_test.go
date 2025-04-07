package pveapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxmoxAPITokenAuthProvider_Authenticate(t *testing.T) {
	provider := &APITokenAuthProvider{
		User:    "user@pve",
		TokenID: "token-id",
		Secret:  "token-secret",
	}

	// Authenticate should always return nil for token auth
	err := provider.Authenticate(context.Background())
	if err != nil {
		t.Errorf("got error %v, want nil", err)
	}
}

func TestProxmoxAPITokenAuthProvider_UpdateRequest(t *testing.T) {
	provider := &APITokenAuthProvider{
		User:    "user@pve",
		TokenID: "token-id",
		Secret:  "token-secret",
	}

	// Create a request to update
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Update the request
	provider.UpdateRequest(req)

	// Check that the Authorization header was set correctly
	expected := "PVEAPIToken=user@pve!token-id=token-secret"
	if got := req.Header.Get("Authorization"); got != expected {
		t.Errorf("got Authorization header %q, want %q", got, expected)
	}
}

func TestProxmoxPasswordAuthProvider_GetClient(t *testing.T) {
	provider := &PasswordAuthProvider{
		proxmoxBaseURL: "https://proxmox.example.com:8006",
		user:           "user@pve",
		password:       "password",
	}

	// First call should create a new client
	client1, err := provider.getClient()
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if client1 == nil {
		t.Fatalf("got nil client, want non-nil")
	}

	// Second call should return the same client
	client2, err := provider.getClient()
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if client2 != client1 {
		t.Errorf("got different client on second call, want same client")
	}
}

func TestProxmoxPasswordAuthProvider_Authenticate(t *testing.T) {
	// Create a test server that simulates the Proxmox API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the request is correct
		if r.URL.Path != "/api2/json/access/ticket" {
			t.Errorf("got path %q, want %q", r.URL.Path, "/api2/json/access/ticket")
		}
		if r.Method != "POST" {
			t.Errorf("got method %q, want %q", r.Method, "POST")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if got := r.Form.Get("username"); got != "user@pve" {
			t.Errorf("got username %q, want %q", got, "user@pve")
		}
		if got := r.Form.Get("password"); got != "password" {
			t.Errorf("got password %q, want %q", got, "password")
		}

		// Send a successful response
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"ticket":              "test-ticket",
				"CSRFPreventionToken": "test-csrf",
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	provider := &PasswordAuthProvider{
		proxmoxBaseURL: server.URL,
		user:           "user@pve",
		password:       "password",
	}

	// Authenticate should succeed and set the ticket and CSRF token
	err := provider.Authenticate(context.Background())
	if err != nil {
		t.Errorf("got error %v, want nil", err)
	}

	// Check that the ticket and CSRF token were set
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.ticket != "test-ticket" {
		t.Errorf("got ticket %q, want %q", provider.ticket, "test-ticket")
	}
	if provider.csrf != "test-csrf" {
		t.Errorf("got CSRF token %q, want %q", provider.csrf, "test-csrf")
	}
}

func TestProxmoxPasswordAuthProvider_Authenticate_Error(t *testing.T) {
	// Create a test server that always returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	provider := &PasswordAuthProvider{
		proxmoxBaseURL: server.URL,
		user:           "user@pve",
		password:       "wrong-password",
	}

	// Authenticate should fail
	err := provider.Authenticate(context.Background())
	if err == nil {
		t.Errorf("got nil error, want non-nil")
	}
}

func TestProxmoxPasswordAuthProvider_UpdateRequest(t *testing.T) {
	provider := &PasswordAuthProvider{
		proxmoxBaseURL: "https://proxmox.example.com:8006",
		user:           "user@pve",
		password:       "password",
		ticket:         "test-ticket",
		csrf:           "test-csrf",
	}

	// Create a request to update
	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Update the request
	provider.UpdateRequest(req)

	// Check that the headers were set correctly
	if got := req.Header.Get("CSRFPreventionToken"); got != "test-csrf" {
		t.Errorf("got CSRFPreventionToken header %q, want %q", got, "test-csrf")
	}
	if got := req.Header.Get("Cookie"); got != "PVEAuthCookie=test-ticket" {
		t.Errorf("got Cookie header %q, want %q", got, "PVEAuthCookie=test-ticket")
	}
}
