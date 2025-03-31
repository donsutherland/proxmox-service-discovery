package main

import (
	"regexp"
	"testing"
)

func TestFilterConfig_FilterResources(t *testing.T) {
	// Create test inventory
	inventory := []pveInventoryItem{
		{
			Name: "vm1",
			Type: pveItemTypeQEMU,
			Tags: []string{"prod", "web"},
		},
		{
			Name: "vm2",
			Type: pveItemTypeLXC,
			Tags: []string{"prod", "db"},
		},
		{
			Name: "vm3",
			Type: pveItemTypeQEMU,
			Tags: []string{"dev", "web"},
		},
	}

	// Test filtering by type
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
			want: []string{"vm1", "vm3"},
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
			want:   []string{"vm1", "vm2", "vm3"},
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
			want: []string{"vm1", "vm2"},
		},
		{
			name: "exclude multiple tags",
			config: FilterConfig{
				ExcludeTags: []string{"dev", "db"},
			},
			want: []string{"vm1"},
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
			want: []string{"vm3"}, // Only vm3 doesn't have tags ending with 'd'
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run filter
			got := tt.config.FilterResources(inventory)

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
				Tags: []string{"test"},
			},
			want: true,
		},
		{
			name: "has matching tag",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: []string{"prod", "web"},
			},
			want: true,
		},
		{
			name: "does not have matching tag",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: []string{"dev", "web"},
			},
			want: false,
		},
		{
			name: "has matching tag regex",
			config: FilterConfig{
				IncludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: []string{"prod-eu", "web"},
			},
			want: true,
		},
		{
			name: "does not have matching tag regex",
			config: FilterConfig{
				IncludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: []string{"dev", "web"},
			},
			want: false,
		},
		{
			name: "empty tags",
			config: FilterConfig{
				IncludeTags: []string{"prod"},
			},
			item: pveInventoryItem{
				Tags: []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.shouldIncludeResourceByTags(tt.item)
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
				Tags: []string{"test"},
			},
			want: false,
		},
		{
			name: "has matching exclude tag",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: []string{"prod", "web"},
			},
			want: true,
		},
		{
			name: "does not have matching exclude tag",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: []string{"prod", "api"},
			},
			want: false,
		},
		{
			name: "has matching exclude tag regex",
			config: FilterConfig{
				ExcludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: []string{"prod-eu", "web"},
			},
			want: true,
		},
		{
			name: "does not have matching exclude tag regex",
			config: FilterConfig{
				ExcludeTagsRe: []*regexp.Regexp{regexp.MustCompile("prod-.*")},
			},
			item: pveInventoryItem{
				Tags: []string{"dev", "web"},
			},
			want: false,
		},
		{
			name: "empty tags",
			config: FilterConfig{
				ExcludeTags: []string{"web"},
			},
			item: pveInventoryItem{
				Tags: []string{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.shouldExcludeResourceByTags(tt.item)
			if got != tt.want {
				t.Errorf("shouldExcludeResourceByTags() = %v, want %v", got, tt.want)
			}
		})
	}
}
