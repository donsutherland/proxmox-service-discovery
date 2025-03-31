package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/oklog/run"
	"github.com/spf13/pflag"

	"github.com/andrew-d/proxmox-service-discovery/internal/pvelog"
)

var (
	proxmoxHost  = pflag.StringP("proxmox-host", "h", "", "Proxmox host to connect to")
	proxmoxUser  = pflag.StringP("proxmox-user", "u", "root@pam", "Proxmox user to connect as")
	dnsZone      = pflag.StringP("dns-zone", "z", "", "DNS zone to serve records for")
	verbose      = pflag.BoolP("verbose", "v", false, "verbose output")
	logResponses = pflag.Bool("log-responses", false, "log all responses from Proxmox")

	// DNS server configuration
	addr = pflag.StringP("addr", "a", ":53", "address to listen on for DNS")
	udp  = pflag.Bool("udp", true, "enable UDP listener")
	tcp  = pflag.Bool("tcp", true, "enable TCP listener")

	// Filtering
	filterType          = pflag.String("filter-type", "", "filter resources by type (e.g. 'qemu' or 'lxc')")
	filterIncludeTags   = pflag.StringArray("filter-include-tags", nil, "if specified, only include resources with these tags")
	filterIncludeTagsRe = pflag.StringArray("filter-include-tags-re", nil, "if specified, only include resources with tags matching these regexes")
	filterExcludeTags   = pflag.StringArray("filter-exclude-tags", nil, "if specified, exclude resources with these tags (takes priority over includes)")
	filterExcludeTagsRe = pflag.StringArray("filter-exclude-tags-re", nil, "if specified, exclude resources with tags matching these regexes (takes priority over includes)")

	// One of these must be set
	proxmoxPassword    = pflag.StringP("proxmox-password", "p", "", "Proxmox password to connect with")
	proxmoxTokenID     = pflag.String("proxmox-token-id", "", "Proxmox API token ID to connect with")
	proxmoxTokenSecret = pflag.String("proxmox-token-secret", "", "Proxmox API token to connect with")
)

var (
	parsedIncludeTagsRe []*regexp.Regexp
	parsedExcludeTagsRe []*regexp.Regexp
)

var (
	logger *slog.Logger = slog.Default()
)

func main() {
	ctx := context.Background()
	pflag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if *proxmoxHost == "" {
		pvelog.Fatal(logger, "--proxmox-host is required")
	}
	if *dnsZone == "" {
		pvelog.Fatal(logger, "--dns-zone is required")
	}
	if ss := *filterIncludeTags; len(ss) > 0 {
		parsedIncludeTagsRe = make([]*regexp.Regexp, len(ss))
		for i, s := range ss {
			parsedIncludeTagsRe[i] = regexp.MustCompile(s)
		}
	}
	if ss := *filterExcludeTags; len(ss) > 0 {
		parsedExcludeTagsRe = make([]*regexp.Regexp, len(ss))
		for i, s := range ss {
			parsedExcludeTagsRe[i] = regexp.MustCompile(s)
		}
	}

	var rg run.Group

	var auth proxmoxAuthProvider
	switch {
	case *proxmoxTokenID != "" && *proxmoxTokenSecret == "":
		pvelog.Fatal(logger, "--proxmox-token-secret is required when --proxmox-token-id is set")
	case *proxmoxTokenID == "" && *proxmoxTokenSecret != "":
		pvelog.Fatal(logger, "--proxmox-token-id is required when --proxmox-token-secret is set")

	case *proxmoxTokenID != "":
		auth = &proxmoxAPITokenAuthProvider{
			user:    *proxmoxUser,
			tokenID: *proxmoxTokenID,
			secret:  *proxmoxTokenSecret,
		}
	case *proxmoxPassword != "":
		auth = &proxmoxPasswordAuthProvider{
			proxmoxBaseURL: *proxmoxHost,
			user:           *proxmoxUser,
			password:       *proxmoxPassword,
		}
	}
	if err := auth.Authenticate(context.Background()); err != nil {
		pvelog.Fatal(logger, "error authenticating with Proxmox", pvelog.Error(err))
	}

	// Periodically call the auth provider's update function.
	authUpdateCtx, authUpdateCancel := context.WithCancel(ctx)
	rg.Add(func() error {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-authUpdateCtx.Done():
				return authUpdateCtx.Err()
			case <-ticker.C:
				if err := auth.Authenticate(authUpdateCtx); err != nil {
					logger.Error("error updating Proxmox auth", pvelog.Error(err))
				}
			}
		}
	}, func(error) {
		authUpdateCancel()
	})

	server := newServer(*proxmoxHost, *dnsZone, auth)

	// Create the DNS server.
	const shutdownTimeout = 5 * time.Second
	if *udp {
		udpServer := &dns.Server{
			Addr:    *addr,
			Net:     "udp",
			Handler: server.dnsMux,
		}
		rg.Add(func() error {
			return udpServer.ListenAndServe()
		}, func(error) {
			shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
			defer cancel()
			udpServer.ShutdownContext(shutdownCtx)
		})
	}
	if *tcp {
		tcpServer := &dns.Server{
			Addr:    *addr,
			Net:     "tcp",
			Handler: server.dnsMux,
		}
		rg.Add(func() error {
			return tcpServer.ListenAndServe()
		}, func(error) {
			shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
			defer cancel()
			tcpServer.ShutdownContext(shutdownCtx)
		})
	}

	// Fetch DNS records at process start so we have a warm cache.
	if err := server.updateDNSRecords(ctx); err != nil {
		// TODO: fatal or not?
		pvelog.Fatal(logger, "error fetching initial DNS records", pvelog.Error(err))
	}

	// Periodically update the DNS records.
	updateCtx, updateCancel := context.WithCancel(ctx)
	rg.Add(func() error {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-updateCtx.Done():
				return nil
			case <-ticker.C:
				if err := server.updateDNSRecords(updateCtx); err != nil {
					logger.Error("error updating DNS records", pvelog.Error(err))
				}
			}
		}
	}, func(error) {
		updateCancel()
	})

	// Shutdown gracefully on SIGINT/SIGTERM
	rg.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))

	logger.Info("proxmox-service-discovery starting")
	defer logger.Info("proxmox-service-discovery finished")

	err := rg.Run()
	if err != nil {
		var signalErr run.SignalError
		if errors.As(err, &signalErr) {
			logger.Info("got signal", "signal", signalErr.Signal)
			return
		}

		logger.Error("error running", pvelog.Error(err))
	}
}

type server struct {
	// config
	host    string
	dnsZone string // with trailing dot
	auth    proxmoxAuthProvider
	client  proxmoxClient

	dnsMux *dns.ServeMux // immutable

	// DNS state
	mu      sync.RWMutex
	records map[string]record
}

// newServer creates a new server instance with the given configuration
func newServer(host, dnsZone string, auth proxmoxAuthProvider) *server {
	if !strings.HasSuffix(dnsZone, ".") {
		dnsZone += "."
	}

	s := &server{
		host:    host,
		dnsZone: dnsZone,
		auth:    auth,
		client:  newDefaultProxmoxClient(host, auth),
		dnsMux:  dns.NewServeMux(),
	}
	s.dnsMux.HandleFunc(dnsZone, s.handleDNSRequest)
	return s
}

type record struct {
	FQDN    string       // the name of the record (e.g. "foo.example.com")
	Type    dns.Type     // the type of the record (e.g. dns.TypeA)
	Answers []netip.Addr // the answer(s) to return (e.g. 192.168.100.200)
}

func (s *server) updateDNSRecords(ctx context.Context) error {
	// Fetch the current inventory
	inventory, err := s.fetchInventory(ctx)
	if err != nil {
		return fmt.Errorf("fetching inventory: %w", err)
	}

	// Filter the inventory to only include resources we care about.
	filtered := filterResources(inventory.Resources)

	// Create the DNS record map.
	records := make(map[string]record)
	for _, item := range filtered {
		fqdn := item.Name + "." + s.dnsZone
		rec := record{
			FQDN: fqdn,
			Type: dns.Type(dns.TypeA),
		}
		for _, addr := range item.Addrs {
			rec.Answers = append(rec.Answers, addr)
		}
		records[fqdn] = rec
	}

	// Update the DNS records
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = records
	return nil
}

func filterResources(inventory []pveInventoryItem) []pveInventoryItem {
	var filtered []pveInventoryItem
	for _, item := range inventory {
		// Filter by type
		if *filterType != "" && item.Type.String() != *filterType {
			continue
		}

		// Filter by tags
		if !shouldIncludeResourceByTags(item) {
			continue
		}
		if shouldExcludeResourceByTags(item) {
			continue
		}

		filtered = append(filtered, item)
	}
	return filtered
}

func shouldIncludeResourceByTags(item pveInventoryItem) bool {
	// If there are no include tags, include everything.
	if len(*filterIncludeTags) == 0 && len(parsedIncludeTagsRe) == 0 {
		return true
	}

	// If there are include tags, include only if the item has at least one
	// of them.
	for _, tag := range *filterIncludeTags {
		if slices.Contains(item.Tags, tag) {
			return true
		}
	}

	// If there are include tag regexes, include only if the item has at
	// least one matching tag.
	// TODO: non-O(n^2) implementation
	for _, tagRe := range parsedIncludeTagsRe {
		for _, tag := range item.Tags {
			if tagRe.MatchString(tag) {
				return true
			}
		}
	}

	return false
}

func shouldExcludeResourceByTags(item pveInventoryItem) bool {
	// If there are no exclude tags, don't exclude anything.
	if len(*filterExcludeTags) == 0 && len(parsedExcludeTagsRe) == 0 {
		return false
	}

	// If there are exclude tags, exclude if the item has any of them.
	for _, tag := range *filterExcludeTags {
		if slices.Contains(item.Tags, tag) {
			return true
		}
	}

	// If there are exclude tag regexes, exclude if the item has any matching
	// tags.
	// TODO: non-O(n^2) implementation
	for _, tagRe := range parsedExcludeTagsRe {
		for _, tag := range item.Tags {
			if tagRe.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

func (s *server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	logger.Debug("DNS request", "question", r.Question)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	s.mu.RLock()
	defer s.mu.RUnlock()

	var found bool
	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			if answers := s.dnsARecordForLocked(q.Name); len(answers) > 0 {
				msg.Answer = append(msg.Answer, answers...)
				found = true
			}

		case dns.TypeAAAA:
			if answers := s.dnsAAAARecordForLocked(q.Name); len(answers) > 0 {
				msg.Answer = append(msg.Answer, answers...)
				found = true
			}
		}
	}

	// If we didn't find any answers, return a "not found" response.
	if !found {
		msg.SetRcode(r, dns.RcodeNameError)
	}

	if err := w.WriteMsg(msg); err != nil {
		logger.Error("writing DNS response", pvelog.Error(err))
	}
}

func (s *server) dnsARecordForLocked(name string) []dns.RR {
	rec, ok := s.records[name]
	if !ok {
		return nil
	}

	var answers []dns.RR
	for _, a := range rec.Answers {
		if !a.Is4() {
			continue
		}

		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{
			Name:   rec.FQDN,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		}
		rr.A = a.AsSlice()
		answers = append(answers, rr)
	}
	return answers
}

func (s *server) dnsAAAARecordForLocked(name string) []dns.RR {
	rec, ok := s.records[name]
	if !ok {
		return nil
	}

	var answers []dns.RR
	for _, a := range rec.Answers {
		if !a.Is6() {
			continue
		}

		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{
			Name:   rec.FQDN,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    60,
		}
		rr.AAAA = a.AsSlice()
		answers = append(answers, rr)
	}
	return answers
}
