// Package main is the PkgWarden CLI entrypoint.
//
// PkgWarden is an open-source repository hardening advisor for
// package-manager and dependency-ingestion configuration. It is explicitly
// not an SCA scanner.
//
// This file is a scaffold; the full scanner is tracked in milestone M0
// (issues PW-001 through PW-010).
package main

import (
	"fmt"
	"os"
)

// version is set by the release workflow via -ldflags at build time.
var version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("pkgwarden %s\n", version)
			return
		case "help", "--help", "-h":
			printHelp()
			return
		}
	}
	printHelp()
}

func printHelp() {
	fmt.Fprintln(os.Stderr, "pkgwarden — repository hardening advisor for package-manager configuration")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "This is a scaffold build. The scanner is not yet implemented.")
	fmt.Fprintln(os.Stderr, "Track progress in milestone M0: Project foundation and scanner core.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  pkgwarden version    print version")
	fmt.Fprintln(os.Stderr, "  pkgwarden help       print this help")
}
