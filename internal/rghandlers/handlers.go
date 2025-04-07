// rghandlers is a package that provides handlers that match the [run.Group]
// API–i.e. a start function and a stop function.
package rghandlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSServer returns a [run.Group]-compatible handler for a DNS server
// that properly starts and gracefully stops the DNS server.
func DNSServer(srv *dns.Server) (func() error, func(error)) {
	const shutdownTimeout = 5 * time.Second
	return func() error {
			return srv.ListenAndServe()
		}, func(error) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			srv.ShutdownContext(shutdownCtx)
		}
}

// Periodic returns a [run.Group]-compatible handler that calls the
// provided function on the provided interval.
//
// Note that if the provided function returns an error, the handler will stop
// calling the function and return the error.
func Periodic(ctx context.Context, interval time.Duration, f func(context.Context) error) (func() error, func(error)) {
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

type httpServerOptions struct {
	Server  *http.Server
	Timeout time.Duration

	// Listener, if set, will be used and [http.Server.Serve] will be
	// called instead of [http.Server.ListenAndServe].
	//
	// This is currently only used in tests.
	Listener net.Listener
}

// httpServerImpl is the implementation of [HTTPServer] with options that we can
// override in tests.
func httpServerImpl(opts httpServerOptions) (func() error, func(error)) {
	// NOTE: the run.Group API will call all stop functions sequentially,
	// so we need to be careful to not block in the interrupt function.
	//
	// We do this by creating a context here that is closed when the
	// Shutdown function returns, and then waiting for that channel in the
	// main execute function.
	var (
		shutdownComplete     = make(chan struct{})
		shutdownCompleteOnce sync.Once
	)

	srv := opts.Server
	execute := func() error {
		var err error
		if opts.Listener != nil {
			err = srv.Serve(opts.Listener)
		} else {
			err = srv.ListenAndServe()
		}

		// Per the documentation on Shutdown: "Make sure the program
		// doesn't exit and waits instead for Shutdown to return"; do
		// that here.
		<-shutdownComplete
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	interrupt := func(error) {
		// Run the shutdown itself in a new goroutine, so we don't
		// block in the interrupt function.
		go func() {
			defer shutdownCompleteOnce.Do(func() {
				close(shutdownComplete)
			})

			// This context is used to bound how long we gracefully
			// wait for the HTTP server to shutdown.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
			defer cancel()
			srv.Shutdown(shutdownCtx)
		}()
	}
	return execute, interrupt
}

// HTTPServer returns a [run.Group]-compatible handler for an HTTP server
// that properly starts and gracefully stops the HTTP server.
func HTTPServer(srv *http.Server) (func() error, func(error)) {
	const shutdownTimeout = 5 * time.Second
	return httpServerImpl(httpServerOptions{
		Server:  srv,
		Timeout: shutdownTimeout,
	})
}
