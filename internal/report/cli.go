package report

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Options are the flags every *forge subcommand accepts. Keeping them in one
// place is what makes the family predictable: an engineer who learned one tool
// already knows the others, and `--fail-on` means the same thing everywhere.
type Options struct {
	JSON    bool
	HTML    bool
	Out     string
	Explain bool
	FailOn  string
	Top     int
}

// Bind registers the shared flags on a flag set.
func (o *Options) Bind(fs *flag.FlagSet, defaultFailOn string) {
	fs.BoolVar(&o.JSON, "json", false, "Machine-readable output, for aggregation or CI.")
	fs.BoolVar(&o.HTML, "html", false, "Self-contained HTML report (no JavaScript, no external assets).")
	fs.StringVar(&o.Out, "out", "", "Write the HTML report to this file instead of stdout.")
	fs.BoolVar(&o.Explain, "explain", false, "Add an AI layer: prose and a real before/after for each finding. Costs tokens; needs ANTHROPIC_API_KEY.")
	fs.StringVar(&o.FailOn, "fail-on", defaultFailOn, "Exit 1 at this severity or above: critical, high, medium, low, info, none.")
	fs.IntVar(&o.Top, "top", 0, "Show only the N worst problems in the text report (0 = all).")
}

// ParseArgs accepts flags and positional arguments in either order.
//
// Go's flag package stops at the first positional argument, so `scan . --json`
// would silently ignore the flag — and a CLI that quietly does the wrong thing
// is worse than one that errors. Reordering solves that, but naively it also
// steals the value of a flag like `--out report.html` and hands it back as the
// path to analyse. So the value-taking flags are known by name, and their value
// travels with them.
func ParseArgs(fs *flag.FlagSet, args []string) []string {
	valueTaking := map[string]bool{"out": true, "fail-on": true, "top": true}

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // --out=file carries its own value
		}
		// Take the next argument as this flag's value, whatever it looks like.
		if valueTaking[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	_ = fs.Parse(append(flags, positional...))
	return fs.Args()
}

// Emit renders the report in whichever format was asked for and returns the
// process exit code. One function for every tool, so the output rules cannot
// drift apart between them.
func (r *Report) Emit(o Options) int {
	switch {
	case o.JSON:
		fmt.Println(r.JSON())
	case o.HTML:
		html := r.HTML()
		if o.Out != "" {
			if err := os.WriteFile(o.Out, []byte(html), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "could not write the report:", err)
				return 2
			}
			fmt.Fprintf(os.Stderr, "%s: wrote %d finding(s) → %s\n", r.Tool, len(r.Findings), o.Out)
		} else {
			fmt.Println(html)
		}
	default:
		fmt.Print(r.Text(o.Top))
	}
	return r.ExitCode(Severity(strings.ToLower(o.FailOn)))
}
