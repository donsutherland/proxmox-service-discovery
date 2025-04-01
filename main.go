package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/oklog/run"
	"github.com/spf13/pflag"

	"github.com/andrew-d/proxmox-service-discovery/internal/buildtags"
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
	rg.Add(PeriodicHandler(ctx, 15*time.Minute, func(ctx context.Context) error {
		// NOTE: we never error here, as we don't want to stop the run.Group.
		if err := auth.Authenticate(ctx); err != nil {
			logger.Error("error updating Proxmox auth", pvelog.Error(err))
		}
		return nil
	}))

	server, err := newServer(*proxmoxHost, *dnsZone, auth)
	if err != nil {
		pvelog.Fatal(logger, "error creating server", pvelog.Error(err))
	}

	// Create the DNS server.
	const shutdownTimeout = 5 * time.Second
	if *udp {
		udpServer := &dns.Server{
			Addr:    *addr,
			Net:     "udp",
			Handler: server.dnsMux,
		}
		rg.Add(DNSServerHandler(udpServer))
	}
	if *tcp {
		tcpServer := &dns.Server{
			Addr:    *addr,
			Net:     "tcp",
			Handler: server.dnsMux,
		}
		rg.Add(DNSServerHandler(tcpServer))
	}

	// Fetch DNS records at process start so we have a warm cache.
	if err := server.updateDNSRecords(ctx); err != nil {
		// TODO: fatal or not? configurable?
		pvelog.Fatal(logger, "error fetching initial DNS records", pvelog.Error(err))
	}

	// Periodically update the DNS records.
	rg.Add(PeriodicHandler(ctx, 1*time.Minute, func(ctx context.Context) error {
		// NOTE: we never error here, as we don't want to stop the
		// run.Group on failure.
		if err := server.updateDNSRecords(ctx); err != nil {
			logger.Error("error updating DNS records", pvelog.Error(err))
		}
		return nil
	}))

	// Shutdown gracefully on SIGINT/SIGTERM
	rg.Add(run.SignalHandler(ctx, syscall.SIGINT, syscall.SIGTERM))

	logger.Info("proxmox-service-discovery starting")
	defer logger.Info("proxmox-service-discovery finished")

	if err := rg.Run(); err != nil {
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
	fc      *FilterConfig

	dnsMux *dns.ServeMux // immutable

	// DNS state
	mu      sync.RWMutex
	records map[string]record
}

// newServer creates a new server instance with the given configuration
func newServer(host, dnsZone string, auth proxmoxAuthProvider) (*server, error) {
	if !strings.HasSuffix(dnsZone, ".") {
		dnsZone += "."
	}

	fc, err := NewFilterConfigFromFlags()
	if err != nil {
		return nil, fmt.Errorf("creating filter config: %w", err)
	}

	s := &server{
		host:    host,
		dnsZone: dnsZone,
		auth:    auth,
		client:  newDefaultProxmoxClient(host, auth),
		fc:      fc,
		dnsMux:  dns.NewServeMux(),
	}
	s.dnsMux.HandleFunc(dnsZone, s.handleDNSRequest)
	return s, nil
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
	filtered := s.fc.FilterResources(inventory.Resources)

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

func (s *server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if buildtags.IsDev {
		logger.Debug("DNS request", "question", r.Question)
	}

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
		logger.Error("error writing DNS response", pvelog.Error(err))
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
