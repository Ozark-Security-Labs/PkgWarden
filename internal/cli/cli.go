package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Ozark-Security-Labs/PkgWarden/internal/model"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/policy"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/reporting"
	"github.com/Ozark-Security-Labs/PkgWarden/internal/scanner"
)

const version = "0.0.0-dev"

func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		writeUsage(stderr)
		return 1
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "pkgwarden %s\n", version)
		return 0
	case "help", "-h", "--help":
		writeUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		writeUsage(stderr)
		return 1
	}
}

func runScan(args []string, stdout io.Writer, stderr io.Writer) int {
	format := "human"
	var profile model.ProfileID
	var policyPath string
	var target string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--format requires a value")
				writeScanUsage(stderr)
				return 1
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--profile":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--profile requires a value")
				writeScanUsage(stderr)
				return 1
			}
			selected, ok := policy.ParseProfile(args[i+1])
			if !ok {
				fmt.Fprintf(stderr, "unsupported profile: %s\n", args[i+1])
				writeScanUsage(stderr)
				return 1
			}
			profile = selected
			i++
		case strings.HasPrefix(arg, "--profile="):
			value := strings.TrimPrefix(arg, "--profile=")
			selected, ok := policy.ParseProfile(value)
			if !ok {
				fmt.Fprintf(stderr, "unsupported profile: %s\n", value)
				writeScanUsage(stderr)
				return 1
			}
			profile = selected
		case arg == "--policy":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--policy requires a value")
				writeScanUsage(stderr)
				return 1
			}
			policyPath = args[i+1]
			i++
		case strings.HasPrefix(arg, "--policy="):
			policyPath = strings.TrimPrefix(arg, "--policy=")
		case strings.HasPrefix(arg, "-"):
			fmt.Fprintf(stderr, "unknown scan option: %s\n", arg)
			writeScanUsage(stderr)
			return 1
		default:
			if target != "" {
				fmt.Fprintf(stderr, "unexpected scan argument: %s\n", arg)
				writeScanUsage(stderr)
				return 1
			}
			target = arg
		}
	}

	if target == "" {
		fmt.Fprintln(stderr, "scan requires a path")
		writeScanUsage(stderr)
		return 1
	}

	report, err := scanner.ScanWithOptions(target, scanner.Options{Profile: profile, PolicyPath: policyPath})
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	switch format {
	case "human":
		err = reporting.WriteHuman(stdout, report)
	case "json":
		err = reporting.WriteJSON(stdout, report)
	default:
		fmt.Fprintf(stderr, "unsupported format: %s\n", format)
		writeScanUsage(stderr)
		return 1
	}
	if err != nil {
		if errors.Is(err, reporting.ErrWriteFailed) {
			fmt.Fprintln(stderr, "failed to write report")
		} else {
			fmt.Fprintf(stderr, "failed to write report: %v\n", err)
		}
		return 1
	}

	return 0
}

func writeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  pkgwarden scan [--format human|json] [--profile baseline|strict|socket-firewall|veracode-package-firewall|private-registry] [--policy path] <path>
  pkgwarden version
  pkgwarden help
`)
}

func writeScanUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  pkgwarden scan [--format human|json] [--profile baseline|strict|socket-firewall|veracode-package-firewall|private-registry] [--policy path] <path>
`)
}
