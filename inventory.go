package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/andrew-d/proxmox-service-discovery/internal/pvelog"
)

// pveInventory is a summary of the state of the Proxmox cluster.
type pveInventory struct {
	// NodeNames is the list of (host) node names in the cluster.
	NodeNames []string
	// Resources is the list of resources in the cluster.
	Resources []pveInventoryItem
}

type pveInventoryItem struct {
	// Name is the name of the resource.
	Name string
	// ID is the (numeric) ID of the resource.
	ID int
	// Node is the name of the node the resource is on.
	Node string
	// Type is the type of the resource.
	Type pveItemType
	// Tags are the tags associated with the resource.
	// TODO: map[string]bool?
	Tags []string
	// Addrs are the IP addresses associated with the resource.
	Addrs []netip.Addr
}

type pveItemType int

const (
	pveItemTypeUnknown pveItemType = iota
	pveItemTypeLXC
	pveItemTypeQEMU
)

func (t pveItemType) String() string {
	switch t {
	case pveItemTypeLXC:
		return "LXC"
	case pveItemTypeQEMU:
		return "QEMU"
	default:
		return "unknown"
	}
}

func (s *server) fetchInventory(ctx context.Context) (inventory pveInventory, _ error) {
	// Start by fetching the list of nodes from the Proxmox API
	nodes, err := fetchFromProxmox[[]Node](ctx, s.host+"/api2/json/nodes", s.auth)
	if err != nil {
		return inventory, fmt.Errorf("fetching nodes: %w", err)
	}

	// For each node, fetch VMs and LXCs.
	var (
		numLXCs int
		numVMs  int
	)
	for _, node := range nodes {
		// Fetch the list of VMs
		vms, err := fetchFromProxmox[[]QEMU](ctx, s.host+"/api2/json/nodes/"+node.Node+"/qemu", s.auth)
		if err != nil {
			return inventory, fmt.Errorf("fetching VMs for node %q: %w", node.Node, err)
		}
		numVMs += len(vms)

		// Add the VMs to the inventory
		for _, vm := range vms {
			// Skip VMs that are not running
			if vm.Status != "running" {
				continue
			}

			// Get the IP address of the VM
			addrs, err := s.fetchQEMUAddrs(ctx, node.Node, vm.VMID)
			if err != nil {
				return inventory, fmt.Errorf("fetching IP addresses for VM %q on %q: %w", vm.VMID, node.Node, err)
			}
			logger.Debug("fetched IP addresses for VM", "vm", vm.Name, "addrs", addrs)

			inventory.Resources = append(inventory.Resources, pveInventoryItem{
				Name:  vm.Name,
				ID:    vm.VMID,
				Node:  node.Node,
				Type:  pveItemTypeQEMU,
				Tags:  strings.Split(vm.Tags, ";"),
				Addrs: addrs,
			})
		}

		// Fetch the list of LXCs
		lxcs, err := fetchFromProxmox[[]LXC](ctx, s.host+"/api2/json/nodes/"+node.Node+"/lxc", s.auth)
		if err != nil {
			return inventory, fmt.Errorf("fetching LXCs for node %q: %w", node.Node, err)
		}
		numLXCs += len(lxcs)

		// Add the LXCs to the inventory
		for _, lxc := range lxcs {
			// Skip LXCs that are not running
			if lxc.Status != "running" {
				continue
			}

			// Get the IP address of the VM
			addrs, err := s.fetchLXCAddrs(ctx, node.Node, lxc.VMID)
			if err != nil {
				return inventory, fmt.Errorf("fetching IP addresses for LXC %q on %q: %w", lxc.VMID, node.Node, err)
			}
			logger.Debug("fetched IP addresses for LXC", "lxc", lxc.Name, "addrs", addrs)

			inventory.Resources = append(inventory.Resources, pveInventoryItem{
				Name:  lxc.Name,
				ID:    lxc.VMID,
				Node:  node.Node,
				Type:  pveItemTypeLXC,
				Tags:  strings.Split(lxc.Tags, ";"),
				Addrs: addrs,
			})
		}
	}

	logger.Debug("fetched inventory from Proxmox",
		"num_nodes", len(nodes),
		"num_vms", numVMs,
		"num_lxcs", numLXCs)

	return inventory, nil
}

func (s *server) fetchQEMUAddrs(ctx context.Context, node string, vmID int) ([]netip.Addr, error) {
	logger := logger.With("vm", vmID, "node", node)

	// Start by seeing if we can find a static IP address in the QEMU config.
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/config", s.host, node, vmID)
	conf, err := fetchFromProxmox[QEMUConfig](ctx, uri, s.auth)
	if err != nil {
		return nil, fmt.Errorf("fetching QEMU config for %q on %q: %w", vmID, node, err)
	}

	if addr, err := netip.ParseAddr(conf.IPConfig0); err == nil {
		return []netip.Addr{addr}, nil
	}

	// Find the hardware address of the first network interface.
	var hwAddr string
	parts := strings.Split(conf.Net0, ",")
	for _, part := range parts {
		if suff, ok := strings.CutPrefix(part, "macaddr="); ok {
			hwAddr = suff
			break
		}
		if suff, ok := strings.CutPrefix(part, "virtio="); ok {
			hwAddr = suff
			break
		}
	}
	if hwAddr == "" {
		logger.Warn("no hardware address found for QEMU guest, returning all IP addresses",
			slog.String("net0", conf.Net0))
	}

	// Otherwise, fetch and return all non-localhost IP addresses from the QEMU guest, if any.
	uri = fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", s.host, node, vmID)
	interfaces, err := fetchFromProxmox[AgentInterfacesResponse](ctx, uri, s.auth)
	if err != nil {
		return nil, fmt.Errorf("fetching QEMU guest interfaces for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched QEMU guest interfaces", "num_interfaces", len(interfaces.Result))

	var addrs []netip.Addr
	for _, iface := range interfaces.Result {
		if iface.Name == "lo" {
			continue
		}

		// If we have a hardware address, only include addresses for that interface.
		if hwAddr != "" && iface.HardwareAddress != hwAddr {
			continue
		}

		for _, addr := range iface.IPAddresses {
			if addr.Type != "ipv4" && addr.Type != "ipv6" {
				continue
			}
			ip, err := netip.ParseAddr(addr.Address)
			if err != nil {
				logger.Error("parsing IP address", "address", addr.Address, pvelog.Error(err))
				continue
			}
			addrs = append(addrs, ip)
		}
	}
	return addrs, nil
}

func (s *server) fetchLXCAddrs(ctx context.Context, node string, vmID int) ([]netip.Addr, error) {
	logger := logger.With("lxc", vmID, "node", node)

	// Fetch the LXC guest config to see if we can find a static IP address.
	uri := fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/config", s.host, node, vmID)
	conf, err := fetchFromProxmox[LXCConfig](ctx, uri, s.auth)
	if err != nil {
		return nil, fmt.Errorf("fetching LXC config for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched LXC config", "config", conf)

	// See if there's a static IP specified in the LXC config.
	var (
		isDHCP bool
		hwAddr string
	)
	parts := strings.Split(conf.Net0, ",")
	for _, part := range parts {
		if suff, ok := strings.CutPrefix(part, "ip="); ok {
			if suff == "dhcp" {
				isDHCP = true
				continue
			}

			// See if we can parse the IP address.
			if pfx, err := netip.ParsePrefix(suff); err == nil {
				return []netip.Addr{pfx.Addr()}, nil
			} else {
				logger.Warn("parsing static IP address",
					slog.String("address", suff),
					pvelog.Error(err))
			}
		}

		// Also grab the hardware address if we can.
		if suff, ok := strings.CutPrefix(part, "hwaddr="); ok {
			hwAddr = suff
		}
	}
	if isDHCP {
		logger.Debug("LXC guest is using DHCP")
	}

	// Fetch and return all non-localhost IP addresses from the LXC guest, if any.
	uri = fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/interfaces", s.host, node, vmID)
	interfaces, err := fetchFromProxmox[[]LXCInterface](ctx, uri, s.auth)
	if err != nil {
		return nil, fmt.Errorf("fetching LXC guest interfaces for %q on %q: %w", vmID, node, err)
	}
	logger.Debug("fetched LXC guest interfaces", "num_interfaces", len(interfaces))

	var addrs []netip.Addr
	for _, iface := range interfaces {
		if iface.Name == "lo" {
			continue
		}
		// If we have a hardware address, only include addresses for that interface.
		if hwAddr != "" && !strings.EqualFold(iface.HardwareAddress, hwAddr) {
			logger.Debug("skipping interface with different hardware address",
				slog.String("interface_name", iface.Name),
				slog.String("interface_hwaddr", iface.HardwareAddress),
				slog.String("expected_hwaddr", hwAddr))
			continue
		}

		if iface.Inet != "" {
			pref, err := netip.ParsePrefix(iface.Inet)
			if err != nil {
				logger.Error("parsing IP prefix", "prefix", iface.Inet, pvelog.Error(err))
				continue
			}
			addrs = append(addrs, pref.Addr())
		}
		if iface.Inet6 != "" {
			pref, err := netip.ParsePrefix(iface.Inet6)
			if err != nil {
				logger.Error("parsing IPv6 prefix", "prefix", iface.Inet6, pvelog.Error(err))
				continue
			}
			addrs = append(addrs, pref.Addr())
		}
	}
	return addrs, nil
}
