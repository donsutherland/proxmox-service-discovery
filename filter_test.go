package main

import (
	"net/netip"
	"regexp"
	"testing"
)

func TestFilterConfig_FilterResources(t *testing.T) {
	// Create test inventory
	inventory := []pveInventoryItem{
		{
			Name: "vm1",
			Type: pveItemTypeQEMU,
			Tags: stringBoolMap("prod", "web"),
			Addrs: []netip.Addr{
				netip.MustParseAddr("192.168.1.10"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
		{
			Name: "vm2",
			Type: pveItemTypeLXC,
			Tags: stringBoolMap("prod", "db"),
			Addrs: []netip.Addr{
				netip.MustParseAddr("192.168.1.20"),
			},
		},
		{
			Name: "vm3",
			Type: pveItemTypeQEMU,
			Tags: stringBoolMap("dev", "web"),
			Addrs: []netip.Addr{
				netip.MustParseAddr("10.0.0.5"),
			},
		},
		{
			Name:  "vm4",
			Type:  pveItemTypeQEMU,
			Tags:  stringBoolMap("test"),
			Addrs: []netip.Addr{}, // No IP addresses
		},
	}

	// Test filtering
	tests := []struct {
		name   string
		config FilterConfig
		want   []string // Names of expected resources
	}{
		{
			name: "filter by type QEMU",
			config: FilterConfig{
				Type: "QEMU",
			},
			want: []string{"vm1", "vm3", "vm4"},
		},
		{
			name: "filter by type LXC",
			config: FilterConfig{
				Type: "LXC",
			},
			want: []string{"vm2"},
		},
		{
			name:   "no type filter",
			config: FilterConfig{},
			want:   []string{"vm1", "vm2", "vm3", "vm4"},
		},
		{
			name: "include tag prod",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			want: []string{"vm1", "vm2"},
		},
		{
			name: "include tag web",
			config: FilterConfig{
				IncludeTags: []string{"web"},
			},
			want: []string{"vm1", "vm3"},
		},
		{
			name: "include multiple tags (any match)",
			config: FilterConfig{
				IncludeTags: []string{"prod", "dev"},
			},
			want: []string{"vm1", "vm2", "vm3"},
		},
		{
			name: "exclude tag dev",
			config: FilterConfig{
				ExcludeTags: []string{"dev"},
			},
			want: []string{"vm1", "vm2", "vm4"},
		},
		{
			name: "exclude multiple tags",
			config: FilterConfig{
				ExcludeTags: []string{"dev", "db"},
			},
			want: []string{"vm1", "vm4"},
		},
		{
			name: "include and exclude tags (exclude has priority)",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
				ExcludeTags: []string{"db"},
			},
			want: []string{"vm1"},
		},
		{
			name: "include tag regex prod.*",
			config: FilterConfig{
				IncludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod.*")},
			},
			want: []string{"vm1", "vm2"},
		},
		{
			name: "exclude tag regex .*d",
			config: FilterConfig{
				ExcludeTagsRe: []*regexp.Regexp{regexp.MustCompile(".*d$")},
			},
			want: []string{"vm3", "vm4"}, // Only vm3/4 don't't have tags ending with 'd'
		},
		{
			name: "include CIDR 192.168.1.0/24",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			want: []string{"vm1", "vm2"},
		},
		{
			name: "include CIDR 10.0.0.0/8",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			want: []string{"vm3"},
		},
		{
			name: "include multiple CIDRs",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			want: []string{"vm1", "vm2", "vm3"},
		},
		{
			name: "include IPv6 CIDR",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			},
			want: []string{"vm1"},
		},
		{
			name: "exclude CIDR 192.168.1.0/24",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			want: []string{"vm3", "vm4"}, // vm4 has no IPs, so it's not excluded
		},
		{
			name: "exclude CIDR 10.0.0.0/8",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			want: []string{"vm1", "vm2", "vm4"},
		},
		{
			name: "exclude multiple CIDRs",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{
					netip.MustParsePrefix("192.168.1.0/24"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			want: []string{"vm4"}, // Only vm4 has no IP in the excluded CIDRs
		},
		{
			name: "include and exclude CIDRs (exclude has priority)",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/28")},
			},
			want: []string{"vm2"}, // vm1 is excluded as 192.168.1.10 is in 192.168.1.0/28
		},
		{
			name: "complex filter with type, tags, and CIDRs",
			config: FilterConfig{
				Type:         "QEMU",
				IncludeTags:  []string{"web"},
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			want: []string{"vm1"}, // vm1 matches all criteria
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run filter
			filt, err := NewFilter(&tt.config)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}
			got := filt.FilterResources(inventory)

			// Check results
			if len(got) != len(tt.want) {
				t.Errorf("got %d resources, want %d", len(got), len(tt.want))
				return
			}

			// Create a map of expected resource names for easy lookup
			wantMap := make(map[string]bool)
			for _, name := range tt.want {
				wantMap[name] = true
			}

			// Check each result
			for _, item := range got {
				if !wantMap[item.Name] {
					t.Errorf("got unexpected resource %q", item.Name)
				}
			}
		})
	}
}

func TestFilterConfig_ShouldIncludeResourceByTags(t *testing.T) {
	tests := []struct {
		name   string
		config FilterConfig
		item   pveInventoryItem
		want   bool
	}{
		{
			name:   "no include filters - should include",
			config: FilterConfig{},
			item: pveInventoryItem{
				Tags: stringBoolMap("test"),
			},
			want: true,
		},
		{
			name: "has matching tag",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("prod", "web"),
			},
			want: true,
		},
		{
			name: "does not have matching tag",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("dev", "web"),
			},
			want: false,
		},
		{
			name: "has matching tag regex",
			config: FilterConfig{
				IncludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("prod-eu", "web"),
			},
			want: true,
		},
		{
			name: "does not have matching tag regex",
			config: FilterConfig{
				IncludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("dev", "web"),
			},
			want: false,
		},
		{
			name: "empty tags",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap(),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filt, err := NewFilter(&tt.config)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}
			got := filt.shouldIncludeResourceByTags(tt.item)
			if got != tt.want {
				t.Errorf("shouldIncludeResourceByTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterConfig_ShouldExcludeResourceByTags(t *testing.T) {
	tests := []struct {
		name   string
		config FilterConfig
		item   pveInventoryItem
		want   bool
	}{
		{
			name:   "no exclude filters - should not exclude",
			config: FilterConfig{},
			item: pveInventoryItem{
				Tags: stringBoolMap("test"),
			},
			want: false,
		},
		{
			name: "has matching exclude tag",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("prod", "web"),
			},
			want: true,
		},
		{
			name: "does not have matching exclude tag",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("prod", "api"),
			},
			want: false,
		},
		{
			name: "has matching exclude tag regex",
			config: FilterConfig{
				ExcludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("prod-eu", "web"),
			},
			want: true,
		},
		{
			name: "does not have matching exclude tag regex",
			config: FilterConfig{
				ExcludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap("dev", "web"),
			},
			want: false,
		},
		{
			name: "empty tags",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: stringBoolMap(),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filt, err := NewFilter(&tt.config)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}
			got := filt.shouldExcludeResourceByTags(tt.item)
			if got != tt.want {
				t.Errorf("shouldExcludeResourceByTags() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterConfig_ShouldIncludeResourceByCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		config FilterConfig
		item   pveInventoryItem
		want   bool
	}{
		{
			name:   "no include filters - should include",
			config: FilterConfig{},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: true,
		},
		{
			name: "has IP in CIDR",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: true,
		},
		{
			name: "has IP in one of multiple CIDRs",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("192.168.1.0/24"),
				},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: true,
		},
		{
			name: "has multiple IPs, one in CIDR",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("192.168.1.10"),
				},
			},
			want: true,
		},
		{
			name: "IP not in CIDR",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: false,
		},
		{
			name: "has IPv6 in CIDR",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name: "empty IP addresses",
			config: FilterConfig{
				IncludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filt, err := NewFilter(&tt.config)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}
			got := filt.shouldIncludeResourceByCIDRs(tt.item)
			if got != tt.want {
				t.Errorf("shouldIncludeResourceByCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterConfig_ShouldExcludeResourceByCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		config FilterConfig
		item   pveInventoryItem
		want   bool
	}{
		{
			name:   "no exclude filters - should not exclude",
			config: FilterConfig{},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: false,
		},
		{
			name: "has IP in excluded CIDR",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: true,
		},
		{
			name: "has IP in one of multiple excluded CIDRs",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("192.168.1.0/24"),
				},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: true,
		},
		{
			name: "has multiple IPs, one in excluded CIDR",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{
					netip.MustParseAddr("10.0.0.5"),
					netip.MustParseAddr("192.168.1.10"),
				},
			},
			want: true,
		},
		{
			name: "IP not in excluded CIDR",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")},
			},
			want: false,
		},
		{
			name: "has IPv6 in excluded CIDR",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			},
			want: true,
		},
		{
			name: "empty IP addresses",
			config: FilterConfig{
				ExcludeCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			},
			item: pveInventoryItem{
				Addrs: []netip.Addr{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filt, err := NewFilter(&tt.config)
			if err != nil {
				t.Fatalf("failed to create filter: %v", err)
			}
			got := filt.shouldExcludeResourceByCIDRs(tt.item)
			if got != tt.want {
				t.Errorf("shouldExcludeResourceByCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCombineRegexps tests the combineRegexps function.
func TestCombineRegexps(t *testing.T) {
	tests := []struct {
		name    string
		regexps []*regexp.Regexp
		inputs  []string
		matches []bool
	}{
		{
			name:    "empty list",
			regexps: []*regexp.Regexp{},
			inputs:  []string{"test", "abc", "xyz"},
			matches: []bool{false, false, false},
		},
		{
			name: "single regexp",
			regexps: []*regexp.Regexp{
				regexp.MustCompile("^test$"),
			},
			inputs:  []string{"test", "tester", "abc"},
			matches: []bool{true, false, false},
		},
		{
			name: "multiple regexps",
			regexps: []*regexp.Regexp{
				regexp.MustCompile("^test$"),
				regexp.MustCompile("^prod-.*"),
				regexp.MustCompile("db$"),
			},
			inputs:  []string{"test", "prod-eu", "mydb", "other", "prod-db"},
			matches: []bool{true, true, true, false, true},
		},
		{
			name: "regexp with special characters",
			regexps: []*regexp.Regexp{
				regexp.MustCompile(`\d+`),
				regexp.MustCompile(`a|b`),
			},
			inputs:  []string{"123", "a", "xyz", "b5"},
			matches: []bool{true, true, false, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			combined := combineRegexps(tt.regexps)

			// If the list is empty, combined should be nil
			if len(tt.regexps) == 0 {
				if combined != nil {
					t.Errorf("expected nil for empty list, got %v", combined)
				}
				return
			}

			// Check that the combined regexp matches what we expect
			for i, input := range tt.inputs {
				actual := combined.MatchString(input)
				if actual != tt.matches[i] {
					t.Errorf("for input %q: got match=%v, want match=%v", input, actual, tt.matches[i])
				}
			}
		})
	}
}
