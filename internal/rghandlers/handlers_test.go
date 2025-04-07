package rghandlers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/oklog/run"
)

func TestPeriodic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callCount int
	var mu sync.Mutex

	// Create a channel to signal when the function is called
	callCh := make(chan struct{}, 10)

	// Create a function that counts calls and signals through the channel
	testFunc := func(ctx context.Context) error {
		mu.Lock()
		callCount++
		mu.Unlock()
		callCh <- struct{}{}
		return nil
	}

	// Create the periodic function with a short interval
	interval := 10 * time.Millisecond
	execute, interrupt := Periodic(ctx, interval, testFunc)

	// Create a run group and add our periodic function
	var g run.Group
	g.Add(execute, interrupt)

	// Run the group in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- g.Run()
	}()

	// Wait for at least one call to happen by waiting on the channel
	<-callCh

	// Interrupt the run group
	cancel()

	// Wait for the run group to finish
	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, want nil or context.Canceled", err)
	}

	// Check that at least one call happened
	mu.Lock()
	if callCount == 0 {
		t.Error("function was not called")
	}
	mu.Unlock()

	// Test with a function that returns an error
	t.Run("error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		fakeErr := errors.New("test error")
		errorFunc := func(ctx context.Context) error { return fakeErr }

		var g2 run.Group
		g2.Add(Periodic(ctx, interval, errorFunc))

		err = g2.Run()
		if err == nil || !errors.Is(err, fakeErr) {
			t.Errorf("got error %v, want %v", err, fakeErr)
		}
	})
}

func makeListener(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	t.Cleanup(func() {
		ln.Close()
	})
	return ln
}

func waitForHTTP(t *testing.T, uri string) *http.Response {
	t.Helper()

	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	const maxWait = 10 * time.Second

	var (
		start = time.Now()
		resp  *http.Response
		err   error
	)
	for {
		if time.Since(start) > maxWait {
			t.Fatalf("timed out waiting for server to start")
		}

		resp, err = client.Get(uri)
		if err == nil {
			t.Cleanup(func() {
				resp.Body.Close()
			})
			return resp
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTPServer(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		var requestReceived sync.WaitGroup
		requestReceived.Add(1)

		// Create a test HTTP server
		mux := http.NewServeMux()
		mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test response"))
			requestReceived.Done()
		})

		// Create a listener for use.
		ln := makeListener(t)
		addr := ln.Addr().String()

		// Create a real HTTP server
		srv := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		// Get the run.Group-compatible functions
		execute, interrupt := httpServerImpl(httpServerOptions{
			Server:   srv,
			Timeout:  100 * time.Millisecond,
			Listener: ln,
		})

		// Create a run group and add our HTTP server
		var g run.Group
		g.Add(execute, interrupt)

		// Start the server in a goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- g.Run()
		}()

		// Retry logic for connection attempts
		uri := "http://" + addr + "/test"
		resp := waitForHTTP(t, uri)

		// Wait for the request to be processed by the server
		waitCh := make(chan struct{})
		go func() {
			requestReceived.Wait()
			close(waitCh)
		}()

		select {
		case <-waitCh:
			// Request was handled
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for request to be handled")
		}

		// Read the response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}

		if string(body) != "test response" {
			t.Errorf("got response %q, want 'test response'", string(body))
		}

		// Call the interrupt function to stop the server
		interrupt(nil)

		// Wait for the server to stop with a timeout
		select {
		case err = <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("got error %v, want nil or http.ErrServerClosed", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for server to stop")
		}
	})

	// Test 2: Test with a connection that stays open beyond shutdown timeout
	t.Run("ShutdownTimeout", func(t *testing.T) {
		// This is the main context that times out if the test takes too long.
		testCtx, testCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer testCancel()

		// Create a blocking channel that we'll use to keep a connection open
		blockCtx, blockCancel := context.WithCancel(context.Background())
		defer blockCancel()
		blockCh := blockCtx.Done()

		// Create a mechanism to signal when the handler starts processing
		handlerStarted := make(chan struct{})

		// Create a server with a handler that blocks
		mux := http.NewServeMux()
		mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/block", func(w http.ResponseWriter, r *http.Request) {
			// Signal that we're handling the request
			close(handlerStarted)

			// Write headers to ensure the connection is established
			w.Header().Set("Content-Type", "text/plain")
			w.(http.Flusher).Flush()

			// Block until the test is complete
			<-blockCh
		})

		ln := makeListener(t)
		addr := ln.Addr().String()
		srv := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		var g run.Group
		g.Add(httpServerImpl(httpServerOptions{
			Server:   srv,
			Timeout:  5 * time.Millisecond,
			Listener: ln,
		}))

		// Create a way to interrupt the rungroup.
		stopCtx, stopCancel := context.WithCancel(testCtx)
		defer stopCancel()
		g.Add(interruptActor(stopCtx))

		// Start the server
		errCh := make(chan error, 1)
		go func() {
			errCh <- g.Run()
		}()

		// Wait for the HTTP server to start
		waitForHTTP(t, "http://"+addr+"/ping")

		// Make a request that will block in a separate goroutine
		clientErrCh := make(chan error, 1)
		go func() {
			_, err := http.Get("http://" + addr + "/block")
			clientErrCh <- err
		}()

		// Wait for the handler to start processing
		startedCh := make(chan struct{})
		go func() {
			select {
			case <-handlerStarted:
				// Handler has started; all good
				close(startedCh)
			case <-testCtx.Done():
				// Test timed out
				return
			}
		}()

		select {
		case <-startedCh:
			// Handler has started
		case <-testCtx.Done():
			t.Fatal("timed out waiting for handler to start")
		}

		// Now stop the server while the connection is still open
		stopCancel()

		// The server should terminate despite the open connection
		// because of the timeout
		select {
		case err := <-errCh:
			// This is what we want - server terminated. Expect a
			// context.Canceled error, since that's how we
			// interrupted our rungroup.
			if err == nil || !errors.Is(err, context.Canceled) {
				t.Errorf("got error %v, want context.Canceled", err)
			}
		case <-testCtx.Done():
			t.Error("server did not terminate within timeout")
		}

		// Clean up by closing the blocking channel
		blockCancel()
	})
}

// interruptActor returns a [run.Group] compatible function pair that shuts
// down the rungroup when the context is canceled.
func interruptActor(ctx context.Context) (func() error, func(error)) {
	ctx, cancel := context.WithCancel(ctx)
	return func() error {
			<-ctx.Done()
			return ctx.Err()
		}, func(error) {
			cancel()
		}

}
