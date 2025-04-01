// Package buildtags contains constants that are set based on build tags. This
// is useful for conditional compilation without having to split code into
// separate files.
package buildtags

// Version is the version of the application.
// This will be overridden by ldflags during the build process.
var Version = "dev"
