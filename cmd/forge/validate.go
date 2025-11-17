package main

import (
	"fmt"
	"os"
	"strings"
)

// validateURL checks if URL is valid
func validateURL(url string, requireHTTP bool) {
	if requireHTTP && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Fprintln(os.Stderr, "❌ Error: Invalid URL - must start with http:// or https://")
		fmt.Fprintf(os.Stderr, "   Got: %s\n", url)
		fmt.Fprintln(os.Stderr, "\n💡 Example: https://httpbin.org/post")
		os.Exit(1)
	}
}
