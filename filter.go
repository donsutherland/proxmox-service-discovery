package main

import (
	"regexp"
	"slices"

	"github.com/spf13/pflag"
)

var (
	filterType          = pflag.String("filter-type", "", "filter resources by type (e.g. 'qemu' or 'lxc')")
	filterIncludeTags   = pflag.StringArray("filter-include-tags", nil, "if specified, only include resources with these tags")
	filterIncludeTagsRe = pflag.StringArray("filter-include-tags-re", nil, "if specified, only include resources with tags matching these regexes")
	filterExcludeTags   = pflag.StringArray("filter-exclude-tags", nil, "if specified, exclude resources with these tags (takes priority over includes)")
	filterExcludeTagsRe = pflag.StringArray("filter-exclude-tags-re", nil, "if specified, exclude resources with tags matching these regexes (takes priority over includes)")
)

// FilterConfig holds the configuration for filtering resources.
type FilterConfig struct {
	// Type defines the resource type filter (e.g., "QEMU" or "LXC").
	Type string

	// IncludeTags are the tags that resources must have to be included.
	// If empty, all resources are included (unless excluded).
	IncludeTags []string

	// IncludeTagsRe are regular expressions to match against resource tags.
	// Resources with at least one tag matching any regex are included.
	IncludeTagsRe []*regexp.Regexp

	// ExcludeTags are the tags that will cause resources to be excluded.
	// This takes priority over inclusion.
	ExcludeTags []string

	// ExcludeTagsRe are regular expressions to match against resource tags.
	// Resources with any tag matching any regex are excluded.
	// This takes priority over inclusion.
	ExcludeTagsRe []*regexp.Regexp
}

// NewFilterConfigFromFlags creates a filter configuration from the global command line flags.
func NewFilterConfigFromFlags() *FilterConfig {
	return &FilterConfig{
		Type:         *filterType,
		IncludeTags:  *filterIncludeTags,
		IncludeTagsRe: parsedIncludeTagsRe,
		ExcludeTags:  *filterExcludeTags,
		ExcludeTagsRe: parsedExcludeTagsRe,
	}
}

// FilterResources filters a list of inventory items according to the filter configuration.
func (fc *FilterConfig) FilterResources(inventory []pveInventoryItem) []pveInventoryItem {
	var filtered []pveInventoryItem
	for _, item := range inventory {
		// Filter by type
		if fc.Type != "" && item.Type.String() != fc.Type {
			continue
		}

		// Filter by tags
		if !fc.shouldIncludeResourceByTags(item) {
			continue
		}
		if fc.shouldExcludeResourceByTags(item) {
			continue
		}

		filtered = append(filtered, item)
	}
	return filtered
}

// shouldIncludeResourceByTags determines if a resource should be included based on tags.
func (fc *FilterConfig) shouldIncludeResourceByTags(item pveInventoryItem) bool {
	// If there are no include tags, include everything.
	if len(fc.IncludeTags) == 0 && len(fc.IncludeTagsRe) == 0 {
		return true
	}

	// If there are include tags, include only if the item has at least one
	// of them.
	for _, tag := range fc.IncludeTags {
		if slices.Contains(item.Tags, tag) {
			return true
		}
	}

	// If there are include tag regexes, include only if the item has at
	// least one matching tag.
	// TODO: non-O(n^2) implementation
	for _, tagRe := range fc.IncludeTagsRe {
		for _, tag := range item.Tags {
			if tagRe.MatchString(tag) {
				return true
			}
		}
	}

	return false
}

// shouldExcludeResourceByTags determines if a resource should be excluded based on tags.
func (fc *FilterConfig) shouldExcludeResourceByTags(item pveInventoryItem) bool {
	// If there are no exclude tags, don't exclude anything.
	if len(fc.ExcludeTags) == 0 && len(fc.ExcludeTagsRe) == 0 {
		return false
	}

	// If there are exclude tags, exclude if the item has any of them.
	for _, tag := range fc.ExcludeTags {
		if slices.Contains(item.Tags, tag) {
			return true
		}
	}

	// If there are exclude tag regexes, exclude if the item has any matching
	// tags.
	// TODO: non-O(n^2) implementation
	for _, tagRe := range fc.ExcludeTagsRe {
		for _, tag := range item.Tags {
			if tagRe.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

// filterResources filters resources using the global flags configuration.
// This is a wrapper around the FilterConfig.FilterResources method to maintain
// backward compatibility.
func filterResources(inventory []pveInventoryItem) []pveInventoryItem {
	fc := NewFilterConfigFromFlags()
	return fc.FilterResources(inventory)
}