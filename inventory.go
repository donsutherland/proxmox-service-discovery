package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/creachadair/taskgroup"

	"github.com/andrew-d/proxmox-service-discovery/internal/pvelog"
)

// pveInventory is a summary of the state of the Proxmox cluster.
type pveInventory struct {
	// NodeNames is the list of (host) node names in the cluster.
	NodeNames []string
	// NodeStats is a summary of the inventory about each node.
	NodeStats map[string]nodeInventoryStats
	// Resources is the list of resources in the cluster.
	Resources []pveInventoryItem
}

// nodeInventoryStats is a summary of the inventory about a single node.
type nodeInventoryStats struct {
	NumVMs  int
	NumLXCs int
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
	Tags map[string]bool
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
	nodes, err := s.client.GetNodes(ctx)
	if err != nil {
		return inventory, fmt.Errorf("fetching nodes: %w", err)
	}
	inventory.NodeStats = make(map[string]nodeInventoryStats, len(nodes))

	// For each node, fetch VMs and LXCs in parallel.
	var (
		g taskgroup.Group

		mu      sync.Mutex
		numLXCs int
		numVMs  int
	)
	for _, node := range nodes {
		// Save node name
		inventory.NodeNames = append(inventory.NodeNames, node.Node)

		g.Go(func() error {
			defer logger.Info("finished fetching inventory from node", "node", node.Node)
			nodeInventory, stats, err := s.fetchInventoryFromNode(ctx, node.Node)
			if err != nil {
				return err
			}

			mu.Lock()
			defer mu.Unlock()

			// Update resources
			inventory.NodeStats[node.Node] = stats
			inventory.Resources = append(inventory.Resources, nodeInventory.Resources...)

			// Update stats
			numLXCs += stats.NumLXCs
			numVMs += stats.NumVMs
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return inventory, fmt.Errorf("fetching inventory from nodes: %w", err)
	}

	logger.Debug("fetched inventory from Proxmox",
		"num_nodes", len(nodes),
		"num_vms", numVMs,
		"num_lxcs", numLXCs)

	return inventory, nil
}

func (s *server) fetchInventoryFromNode(ctx context.Context, node string) (inventory pveInventory, stats nodeInventoryStats, _ error) {
	logger := logger.With("node", node)

	// Fetch the list of VMs
	vms, err := s.client.GetQEMUVMs(ctx, node)
	if err != nil {
		return inventory, stats, fmt.Errorf("fetching VMs for node %q: %w", node, err)
	}
	stats.NumVMs = len(vms)

	// Add the VMs to the inventory
	for _, vm := range vms {
		// Skip VMs that are not running
		if vm.Status != "running" {
			continue
		}

		// Get the IP address of the VM
		addrs, err := s.fetchQEMUAddrs(ctx, node, vm.VMID)
		if err != nil {
			return inventory, stats, fmt.Errorf("fetching IP addresses for VM %q on %q: %w", vm.VMID, node, err)
		}
		logger.Debug("fetched IP addresses for VM", "vm", vm.Name, "addrs", addrs)

		inventory.Resources = append(inventory.Resources, pveInventoryItem{
			Name:  vm.Name,
			ID:    vm.VMID,
			Node:  node,
			Type:  pveItemTypeQEMU,
			Tags:  stringBoolMap(strings.Split(vm.Tags, ";")...),
			Addrs: addrs,
		})
	}

	// Fetch the list of LXCs
	lxcs, err := s.client.GetLXCs(ctx, node)
	if err != nil {
		return inventory, stats, fmt.Errorf("fetching LXCs for node %q: %w", node, err)
	}
	stats.NumLXCs = len(vms)

	// Add the LXCs to the inventory
	for _, lxc := range lxcs {
		// Skip LXCs that are not running
		if lxc.Status != "running" {
			continue
		}

		// Get the IP address of the VM
		addrs, err := s.fetchLXCAddrs(ctx, node, lxc.VMID)
		if err != nil {
			return inventory, stats, fmt.Errorf("fetching IP addresses for LXC %q on %q: %w", lxc.VMID, node, err)
		}
		logger.Debug("fetched IP addresses for LXC", "lxc", lxc.Name, "addrs", addrs)

		inventory.Resources = append(inventory.Resources, pveInventoryItem{
			Name:  lxc.Name,
			ID:    lxc.VMID,
			Node:  node,
			Type:  pveItemTypeLXC,
			Tags:  stringBoolMap(strings.Split(lxc.Tags, ";")...),
			Addrs: addrs,
		})
	}
	return inventory, stats, nil
}

func stringBoolMap(from ...string) map[string]bool {
	m := make(map[string]bool, len(from))
	for _, s := range from {
		m[s] = true
	}
	return m
}

func (s *server) fetchQEMUAddrs(ctx context.Context, node string, vmID int) ([]netip.Addr, error) {
	logger := logger.With("vm", vmID, "node", node)

	// Start by seeing if we can find a static IP address in the QEMU config.
	conf, err := s.client.GetQEMUConfig(ctx, node, vmID)
	if err != nil {
		return nil, fmt.Errorf("fetching QEMU config for %q on %q: %w", vmID, node, err)
	}

	// The ipconfig0 field is a comma-separated list of key-value pairs,
	// used to pass configuration to cloud-init; see the following for more
	// information:
	//    https://pve.proxmox.com/pve-docs/chapter-qm.html#qm_cloudinit
	//
	// Split and see if there's an "ip" key.
	ipConfig := splitKVs(conf.IPConfig0)
	if ip, ok := ipConfig["ip"]; ok {
		if pfx, err := netip.ParsePrefix(ip); err == nil {
			return []netip.Addr{pfx.Addr()}, nil
		} else {
			logger.Warn("parsing static IP address",
				slog.String("address", ip),
				pvelog.Error(err))
		}
	}

	// Find the hardware address of the first network interface.
	netConfig := splitKVs(conf.Net0)

	var hwAddr string
	for _, key := range []string{"macaddr", "virtio"} {
		if addr, ok := netConfig[key]; ok {
			hwAddr = addr
			break
		}
	}
	if hwAddr == "" {
		logger.Warn("no hardware address found for QEMU guest, returning all IP addresses",
			slog.String("net0", conf.Net0))
	}

	// Otherwise, fetch and return all non-localhost IP addresses from the QEMU guest, if any.
	interfaces, err := s.client.GetQEMUInterfaces(ctx, node, vmID)
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
	conf, err := s.client.GetLXCConfig(ctx, node, vmID)
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
	if hwAddr == "" {
		logger.Warn("no hardware address found for LXC guest, returning all IP addresses",
			slog.String("net0", conf.Net0))
	}

	// Fetch and return all non-localhost IP addresses from the LXC guest, if any.
	interfaces, err := s.client.GetLXCInterfaces(ctx, node, vmID)
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

func splitKVs(s string) map[string]string {
	if len(s) == 0 {
		return nil
	}

	kvs := make(map[string]string)
	for _, kv := range strings.Split(s, ",") {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		kvs[key] = value
	}
	return kvs
}
