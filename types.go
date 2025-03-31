package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// Node is the API response for a single Proxmox node from the Proxmox API
// /api/json2/nodes endpoint.
type Node struct {
	Node string `json:"node"`
}

// LXC is the API response for a single Proxmox LXC container from the Proxmox
// API /api/json2/nodes/<node>/lxc endpoint.
type LXC struct {
	VMID   int    `json:"vmid"`
	Status string `json:"status"`
	Tags   string `json:"tags"`
	Name   string `json:"name"`
}

// QEMU is the API response for a single Proxmox QEMU VM from the Proxmox API
// /api/json2/nodes/<node>/qemu endpoint.
type QEMU struct {
	VMID   int    `json:"vmid"`
	Status string `json:"status"`
	Tags   string `json:"tags"`
	Name   string `json:"name"`
}

func fetchFromProxmox[T any](ctx context.Context, uri string, auth proxmoxAuthProvider) (T, error) {
	var zero T

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return zero, fmt.Errorf("creating HTTP request: %w", err)
	}
	auth.UpdateRequest(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if *verbose && false {
		var buf bytes.Buffer
		reader = io.TeeReader(resp.Body, &buf)

		defer func() {
			logger.Debug("got response from server",
				slog.String("uri", uri),
				slog.String("status", resp.Status),
				slog.String("response", buf.String()),
			)
		}()
	}

	// All data in Proxmox is returned under the "Data" key.
	var ret struct {
		Data T `json:"data"`
	}
	if err := json.NewDecoder(reader).Decode(&ret); err != nil {
		return zero, fmt.Errorf("decoding response: %w", err)
	}

	return ret.Data, nil
}
