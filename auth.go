package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// proxmoxAuthProvider is an interface for things that can authenticate with
// the Proxmox API.
type proxmoxAuthProvider interface {
	// Authenticate should be called at creation time and every hour to
	// obtain a valid authentication ticket for the Proxmox API.
	Authenticate(context.Context) error

	// UpdateRequest should be called before making a request to the Proxmox
	// API to ensure the request is authenticated.
	UpdateRequest(r *http.Request)
}

// proxmoxAPITokenAuthProvider is an implementation of [proxmoxAuthProvider]
// that uses a Proxmox API token for authentication.
type proxmoxAPITokenAuthProvider struct {
	user    string
	tokenID string
	secret  string
}

func (a *proxmoxAPITokenAuthProvider) Authenticate(_ context.Context) error {
	return nil // no authentication needed
}

func (a *proxmoxAPITokenAuthProvider) UpdateRequest(r *http.Request) {
	token := fmt.Sprintf("%s!%s=%s", a.user, a.tokenID, a.secret)
	r.Header.Set("Authorization", "PVEAPIToken="+token)
}

// proxmoxPasswordAuthProvider is an implementation of [proxmoxAuthProvider]
// that uses a username and password for authentication, periodically
// refreshing the authentication ticket.
type proxmoxPasswordAuthProvider struct {
	proxmoxBaseURL string // immutable; e.g. "https://proxmox.example.com:8006"
	user           string // immutable; the user to authenticate as
	password       string // immutable; the password to authenticate with

	mu     sync.RWMutex
	client *http.Client // the HTTP client to use; created on first use
	ticket string       // the current authentication ticket
	csrf   string       // the current CSRF token
}

func (a *proxmoxPasswordAuthProvider) getClient() (*http.Client, error) {
	a.mu.RLock()
	client := a.client
	a.mu.RUnlock()

	if client != nil {
		return client, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("creating cookie jar: %w", err)
		}
		client = &http.Client{
			Jar: jar,
		}
		a.client = client
	}
	return a.client, nil
}

func (a *proxmoxPasswordAuthProvider) Authenticate(ctx context.Context) error {
	client, err := a.getClient()
	if err != nil {
		return err
	}

	uri := fmt.Sprintf("%s/api2/json/access/ticket", a.proxmoxBaseURL)

	body := url.Values{
		"username": {a.user},
		"password": {a.password},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", uri, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending authentication HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var data struct {
		Data struct {
			Ticket string `json:"ticket"`
			CSRF   string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.ticket = data.Data.Ticket
	a.csrf = data.Data.CSRF
	return nil
}

func (a *proxmoxPasswordAuthProvider) UpdateRequest(r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r.Header.Set("CSRFPreventionToken", a.csrf)
	r.Header.Set("Cookie", "PVEAuthCookie="+a.ticket)
}
