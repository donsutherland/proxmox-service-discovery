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

// QEMUConfig is the API response for the configuration of a Proxmox QEMU VM from
// the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/config endpoint.
type QEMUConfig struct {
	Net0      string `json:"net0"`
	IPConfig0 string `json:"ipconfig0"`
}

// AgentInterfacesResponse is the API response for the agent interface of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterfacesResponse struct {
	Result []AgentInterface `json:"result"`
}

// AgentInterface is the API response for a single agent interface of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterface struct {
	Name            string                  `json:"name"`
	HardwareAddress string                  `json:"hardware-address"`
	IPAddresses     []AgentInterfaceAddress `json:"ip-addresses"`
}

// AgentInterfaceAddress is the API response for a single IP address of a Proxmox QEMU VM
// from the Proxmox API /api2/json/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces endpoint.
type AgentInterfaceAddress struct {
	Type    string `json:"ip-address-type"`
	Address string `json:"ip-address"`
	Prefix  int    `json:"prefix"`
}

// LXCInterface is the API response for a single interface of a Proxmox LXC container
// from the Proxmox API /api2/json/nodes/<node>/lxc/<vmid>/interfaces endpoint.
type LXCInterface struct {
	Name            string `json:"name"`
	HardwareAddress string `json:"hwaddr"`
	Inet            string `json:"inet"`
	Inet6           string `json:"inet6"`
}

// LXCConfig is the API response for the configuration of a Proxmox LXC container
// from the Proxmox API /api2/json/nodes/<node>/lxc/<vmid>/config endpoint.
type LXCConfig struct {
	Net0 string `json:"net0"`
}

// proxmoxClient defines the interface for making requests to the Proxmox API.
// This interface allows for mocking in tests.
type proxmoxClient interface {
	// GetNodes retrieves the list of nodes from the Proxmox API
	GetNodes(ctx context.Context) ([]Node, error)

	// GetQEMUVMs retrieves the list of QEMU VMs for a given node
	GetQEMUVMs(ctx context.Context, node string) ([]QEMU, error)

	// GetLXCs retrieves the list of LXC containers for a given node
	GetLXCs(ctx context.Context, node string) ([]LXC, error)

	// GetQEMUConfig retrieves the configuration of a QEMU VM
	GetQEMUConfig(ctx context.Context, node string, vmID int) (QEMUConfig, error)

	// GetQEMUInterfaces retrieves the network interfaces of a QEMU VM
	GetQEMUInterfaces(ctx context.Context, node string, vmID int) (AgentInterfacesResponse, error)

	// GetLXCConfig retrieves the configuration of an LXC container
	GetLXCConfig(ctx context.Context, node string, vmID int) (LXCConfig, error)

	// GetLXCInterfaces retrieves the network interfaces of an LXC container
	GetLXCInterfaces(ctx context.Context, node string, vmID int) ([]LXCInterface, error)
}

// defaultProxmoxClient is the default implementation of proxmoxClient that
// makes actual HTTP requests to the Proxmox API.
type defaultProxmoxClient struct {
	host string
	auth proxmoxAuthProvider
}

// newDefaultProxmoxClient creates a new default Proxmox client
func newDefaultProxmoxClient(host string, auth proxmoxAuthProvider) *defaultProxmoxClient {
	return &defaultProxmoxClient{
		host: host,
		auth: auth,
	}
}

func (c *defaultProxmoxClient) GetNodes(ctx context.Context) ([]Node, error) {
	return fetchFromProxmox[[]Node](c, ctx, c.host+"/api2/json/nodes")
}

func (c *defaultProxmoxClient) GetQEMUVMs(ctx context.Context, node string) ([]QEMU, error) {
	return fetchFromProxmox[[]QEMU](c, ctx, c.host+"/api2/json/nodes/"+node+"/qemu")
}

func (c *defaultProxmoxClient) GetLXCs(ctx context.Context, node string) ([]LXC, error) {
	return fetchFromProxmox[[]LXC](c, ctx, c.host+"/api2/json/nodes/"+node+"/lxc")
}

func (c *defaultProxmoxClient) GetQEMUConfig(ctx context.Context, node string, vmID int) (QEMUConfig, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/config", c.host, node, vmID)
	return fetchFromProxmox[QEMUConfig](c, ctx, uri)
}

func (c *defaultProxmoxClient) GetQEMUInterfaces(ctx context.Context, node string, vmID int) (AgentInterfacesResponse, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", c.host, node, vmID)
	return fetchFromProxmox[AgentInterfacesResponse](c, ctx, uri)
}

func (c *defaultProxmoxClient) GetLXCConfig(ctx context.Context, node string, vmID int) (LXCConfig, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/config", c.host, node, vmID)
	return fetchFromProxmox[LXCConfig](c, ctx, uri)
}

func (c *defaultProxmoxClient) GetLXCInterfaces(ctx context.Context, node string, vmID int) ([]LXCInterface, error) {
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", c.host, node, vmID)
	return fetchFromProxmox[[]LXCInterface](c, ctx, uri)
}

func fetchFromProxmox[T any](c *defaultProxmoxClient, ctx context.Context, uri string) (T, error) {
	var zero T

	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return zero, fmt.Errorf("creating HTTP request: %w", err)
	}
	c.auth.UpdateRequest(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if *logResponses {
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
