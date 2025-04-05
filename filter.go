package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/spf13/pflag"
	"go4.org/netipx"
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

	// ExcludeTags are the tags that will cause resources to be excluded.
	// This takes priority over inclusion.
	ExcludeTags []string

	// ExcludeTagsRe are regular expressions to match against resource tags.
	// Resources with any tag matching any regex are excluded.
	// This takes priority over inclusion.
	ExcludeTagsRe []*regexp.Regexp

	// IncludeCIDRs are the network CIDRs that resources must have an IP in to be included.
	// If empty, all resources are included (unless excluded).
	IncludeCIDRs []netip.Prefix

	// ExcludeCIDRs are the network CIDRs that will cause resources to be excluded.
	// This takes priority over inclusion.
	ExcludeCIDRs []netip.Prefix
}

// Filter is a compiled representation of the filter configuration.
type Filter struct {
	typeFilter    string
	includeTags   []string
	includeTagsRe *regexp.Regexp // combined regex for all IncludeTagsRe
	excludeTags   []string
	excludeTagsRe *regexp.Regexp // combined regex for all ExcludeTagsRe

	// We can use a BART table or something if we see this becoming a
	// performance bottleneck; I assume that most of the time, the number
	// of CIDRs will be small, and this does a binary search.
	//
	// If we need to switch to another package, here's two options:
	//	- https://github.com/aromatt/netipds
	//	- https://github.com/gaissmai/bart
	//
	// In the vanishingly unlikely event that we need to care about
	// benchmarks, look at: https://github.com/gaissmai/iprbench
	includeCIDRs *netipx.IPSet
	excludeCIDRs *netipx.IPSet
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

// NewFilter creates a new filter based on the provided configuration.
func NewFilter(fc *FilterConfig) (*Filter, error) {
	f := &Filter{
		typeFilter:  fc.Type,
		includeTags: fc.IncludeTags,
		excludeTags: fc.ExcludeTags,
	}

	// Create an IPSet from the include/exclude CIDRs
	if len(fc.IncludeCIDRs) > 0 {
		var builder netipx.IPSetBuilder
		for _, cidr := range fc.IncludeCIDRs {
			builder.AddPrefix(cidr)
		}
		set, err := builder.IPSet()
		if err != nil {
			return nil, fmt.Errorf("creating include CIDR set: %w", err)
		}
		f.includeCIDRs = set
	}
	if len(fc.ExcludeCIDRs) > 0 {
		var builder netipx.IPSetBuilder
		for _, cidr := range fc.ExcludeCIDRs {
			builder.AddPrefix(cidr)
		}
		set, err := builder.IPSet()
		if err != nil {
			return nil, fmt.Errorf("creating exclude CIDR set: %w", err)
		}
		f.excludeCIDRs = set
	}
	// Combine the IncludeTagsRe and ExcludeTagsRe into a single regex
	if len(fc.IncludeTagsRe) > 0 {
		f.includeTagsRe = combineRegexps(fc.IncludeTagsRe)
	}
	if len(fc.ExcludeTagsRe) > 0 {
		f.excludeTagsRe = combineRegexps(fc.ExcludeTagsRe)
	}
	return f, nil
}

// FilterResources filters a list of inventory items according to the filter configuration.
func (f *Filter) FilterResources(inventory []pveInventoryItem) []pveInventoryItem {
	var filtered []pveInventoryItem
	for _, item := range inventory {
		// Filter by type
		if f.typeFilter != "" && item.Type.String() != f.typeFilter {
			continue
		}

		// Filter by tags
		if !f.shouldIncludeResourceByTags(item) {
			continue
		}
		if f.shouldExcludeResourceByTags(item) {
			continue
		}

		// Filter by CIDRs
		if !f.shouldIncludeResourceByCIDRs(item) {
			continue
		}
		if f.shouldExcludeResourceByCIDRs(item) {
			continue
		}

		filtered = append(filtered, item)
	}
	return filtered
}

// shouldIncludeResourceByTags determines if a resource should be included based on tags.
func (f *Filter) shouldIncludeResourceByTags(item pveInventoryItem) bool {
	// If there are no include tags, include everything.
	if len(f.includeTags) == 0 && f.includeTagsRe == nil {
		return true
	}

	// If there are include tags, include only if the item has at least one
	// of them.
	for _, tag := range f.includeTags {
		if item.Tags[tag] {
			return true
		}
	}

	// If there are include tag regexes, include only if the item has at
	// least one matching tag.
	if f.includeTagsRe != nil {
		for tag := range item.Tags {
			if f.includeTagsRe.MatchString(tag) {
				return true
			}
		}
	}

	return false
}

// shouldExcludeResourceByTags determines if a resource should be excluded based on tags.
func (f *Filter) shouldExcludeResourceByTags(item pveInventoryItem) bool {
	// If there are no exclude tags, don't exclude anything.
	if len(f.excludeTags) == 0 && f.excludeTagsRe == nil {
		return false
	}

	// If there are exclude tags, exclude if the item has any of them.
	for _, tag := range f.excludeTags {
		if item.Tags[tag] {
			return true
		}
	}

	// If there are exclude tag regexes, exclude if the item has any matching
	// tags.
	if f.excludeTagsRe != nil {
		for tag := range item.Tags {
			if f.excludeTagsRe.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

// shouldIncludeResourceByCIDRs determines if a resource should be included based on CIDRs.
func (f *Filter) shouldIncludeResourceByCIDRs(item pveInventoryItem) bool {
	// If there are no include CIDRs, include everything.
	if f.includeCIDRs == nil {
		return true
	}

	// If the resource has no IP addresses, don't include it when filtering by CIDR.
	if len(item.Addrs) == 0 {
		return false
	}

	// If there are include CIDRs, include only if the item has at least one
	// IP address within any of the CIDRs.
	for _, ip := range item.Addrs {
		if f.includeCIDRs.Contains(ip) {
			return true
		}
	}

	return false
}

// shouldExcludeResourceByCIDRs determines if a resource should be excluded based on CIDRs.
func (f *Filter) shouldExcludeResourceByCIDRs(item pveInventoryItem) bool {
	// If there are no exclude CIDRs, don't exclude anything.
	if f.excludeCIDRs == nil {
		return false
	}

	// If the resource has no IP addresses, don't exclude it when filtering by CIDR.
	if len(item.Addrs) == 0 {
		return false
	}

	// If there are exclude CIDRs, exclude if the item has any IP address
	// within any of the CIDRs.
	for _, ip := range item.Addrs {
		if f.excludeCIDRs.Contains(ip) {
			return true
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
