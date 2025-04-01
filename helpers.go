package main

import (
	"context"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// DNSServerHandler returns a [run.Group]-compatible handler for a DNS server
// that properly starts and gracefully stops the DNS server.
func DNSServerHandler(srv *dns.Server) (func() error, func(error)) {
	const shutdownTimeout = 5 * time.Second
	return func() error {
			return srv.ListenAndServe()
		}, func(error) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			srv.ShutdownContext(shutdownCtx)
		}
}

// PeriodicHandler returns a [run.Group]-compatible handler that calls the
// provided function on the provided interval.
//
// Note that if the provided function returns an error, the handler will stop
// calling the function and return the error.
func PeriodicHandler(ctx context.Context, interval time.Duration, f func(context.Context) error) (func() error, func(error)) {
	ctx, cancel := context.WithCancel(ctx)
	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ticker.C:
					if err := f(ctx); err != nil {
						return err
					}
				}
			}
		}, func(error) {
			cancel()
		}
}

// HTTPServerHandler returns a [run.Group]-compatible handler for an HTTP server
// that properly starts and gracefully stops the HTTP server.
func HTTPServerHandler(srv *http.Server) (func() error, func(error)) {
	const shutdownTimeout = 5 * time.Second
	return func() error {
			return srv.ListenAndServe()
		}, func(error) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			srv.Shutdown(shutdownCtx)
		}
}
