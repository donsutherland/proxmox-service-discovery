package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/spf13/pflag"
)

var (
	filterType          = pflag.String("filter-type", "", "filter resources by type (e.g. 'qemu' or 'lxc')")
	filterIncludeTags   = pflag.StringArray("filter-include-tags", nil, "if specified, only include resources with these tags")
	filterIncludeTagsRe = pflag.StringArray("filter-include-tags-re", nil, "if specified, only include resources with tags matching these regexes")
	filterExcludeTags   = pflag.StringArray("filter-exclude-tags", nil, "if specified, exclude resources with these tags (takes priority over includes)")
	filterExcludeTagsRe = pflag.StringArray("filter-exclude-tags-re", nil, "if specified, exclude resources with tags matching these regexes (takes priority over includes)")
	filterIncludeCIDRs  = pflag.StringArray("filter-include-cidrs", nil, "if specified, only include resources with IP addresses in these CIDRs")
	filterExcludeCIDRs  = pflag.StringArray("filter-exclude-cidrs", nil, "if specified, exclude resources with IP addresses in these CIDRs (takes priority over includes)")
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

	// combinedIncludeTagsRe is a single regex that combines all the
	// IncludeTagsRe patterns. It is initialized lazily when needed.
	combinedIncludeTagsRe *regexp.Regexp

	// ExcludeTags are the tags that will cause resources to be excluded.
	// This takes priority over inclusion.
	ExcludeTags []string

	// ExcludeTagsRe are regular expressions to match against resource tags.
	// Resources with any tag matching any regex are excluded.
	// This takes priority over inclusion.
	ExcludeTagsRe []*regexp.Regexp

	// combinedExcludeTagsRe is a single regex that combines all the
	// ExcludeTagsRe patterns. It is initialized lazily when needed.
	combinedExcludeTagsRe *regexp.Regexp

	// IncludeCIDRs are the network CIDRs that resources must have an IP in to be included.
	// If empty, all resources are included (unless excluded).
	IncludeCIDRs []netip.Prefix

	// ExcludeCIDRs are the network CIDRs that will cause resources to be excluded.
	// This takes priority over inclusion.
	ExcludeCIDRs []netip.Prefix
}

// NewFilterConfigFromFlags creates a filter configuration from the global command line flags.
func NewFilterConfigFromFlags() (*FilterConfig, error) {
	fc := &FilterConfig{
		Type:          *filterType,
		IncludeTags:   *filterIncludeTags,
		IncludeTagsRe: parsedIncludeTagsRe,
		ExcludeTags:   *filterExcludeTags,
		ExcludeTagsRe: parsedExcludeTagsRe,
	}

	// The combined regular expressions will be initialized lazily when needed

	// Parse CIDRs
	for _, cidr := range *filterIncludeCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid include CIDR %q: %w", cidr, err)
		}
		fc.IncludeCIDRs = append(fc.IncludeCIDRs, prefix)
	}

	for _, cidr := range *filterExcludeCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %q: %w", cidr, err)
		}
		fc.ExcludeCIDRs = append(fc.ExcludeCIDRs, prefix)
	}

	return fc, nil
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

		// Filter by CIDRs
		if !fc.shouldIncludeResourceByCIDRs(item) {
			continue
		}
		if fc.shouldExcludeResourceByCIDRs(item) {
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
		if item.Tags[tag] {
			return true
		}
	}

	// If there are include tag regexes, include only if the item has at
	// least one matching tag.
	if len(fc.IncludeTagsRe) > 0 {
		// Lazy initialization of combined regex
		if fc.combinedIncludeTagsRe == nil {
			fc.combinedIncludeTagsRe = combineRegexps(fc.IncludeTagsRe)
		}

		for tag := range item.Tags {
			if fc.combinedIncludeTagsRe.MatchString(tag) {
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
		if item.Tags[tag] {
			return true
		}
	}

	// If there are exclude tag regexes, exclude if the item has any matching
	// tags.
	if len(fc.ExcludeTagsRe) > 0 {
		// Lazy initialization of combined regex
		if fc.combinedExcludeTagsRe == nil {
			fc.combinedExcludeTagsRe = combineRegexps(fc.ExcludeTagsRe)
		}

		for tag := range item.Tags {
			if fc.combinedExcludeTagsRe.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

// shouldIncludeResourceByCIDRs determines if a resource should be included based on CIDRs.
func (fc *FilterConfig) shouldIncludeResourceByCIDRs(item pveInventoryItem) bool {
	// If there are no include CIDRs, include everything.
	if len(fc.IncludeCIDRs) == 0 {
		return true
	}

	// If the resource has no IP addresses, don't include it when filtering by CIDR.
	if len(item.Addrs) == 0 {
		return false
	}

	// If there are include CIDRs, include only if the item has at least one
	// IP address within any of the CIDRs.
	for _, ip := range item.Addrs {
		for _, cidr := range fc.IncludeCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// shouldExcludeResourceByCIDRs determines if a resource should be excluded based on CIDRs.
func (fc *FilterConfig) shouldExcludeResourceByCIDRs(item pveInventoryItem) bool {
	// If there are no exclude CIDRs, don't exclude anything.
	if len(fc.ExcludeCIDRs) == 0 {
		return false
	}

	// If the resource has no IP addresses, don't exclude it when filtering by CIDR.
	if len(item.Addrs) == 0 {
		return false
	}

	// If there are exclude CIDRs, exclude if the item has any IP address
	// within any of the CIDRs.
	for _, ip := range item.Addrs {
		for _, cidr := range fc.ExcludeCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// combineRegexps combines multiple regular expressions into a single one using
// the | operator.
//
// It returns nil if the input slice is empty.
func combineRegexps(regexps []*regexp.Regexp) *regexp.Regexp {
	if len(regexps) == 0 {
		return nil
	}

	if len(regexps) == 1 {
		return regexps[0]
	}

	// Extract the patterns from each regexp
	patterns := make([]string, len(regexps))
	for i, re := range regexps {
		// Use the String() method to get the pattern with proper escaping
		patterns[i] = re.String()
	}

	// Combine all patterns with the OR operator
	combinedPattern := "(?:" + strings.Join(patterns, ")|(?:") + ")"

	// Compile the combined pattern
	combined, err := regexp.Compile(combinedPattern)
	if err != nil {
		// This should never happen if all input regexps are valid
		panic(fmt.Sprintf("failed to combine regexps: %v", err))
	}

	return combined
}
