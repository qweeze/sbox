package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	flag "github.com/spf13/pflag"

	"github.com/qweeze/sbox/internal/profile"
)

var autoIgnoreFiles = []string{
	".aiderignore",
	".aiexclude",
	".aiignore",
	".augmentignore",
	".clineignore",
	".codeiumignore",
	".continueignore",
	".cursorignore",
	".geminiignore",
	".rooignore",
}

type patternInputs struct {
	Patterns    []profile.Pattern
	AbsPaths    []profile.AbsPath
	LoadedFiles []string
}

func main() {
	var (
		denyPatterns []string
		extraFiles   []string
		root         string
		verbose      bool
		dryRun       bool
		denyWrite    bool
		denyNet      bool
		noAutoIgnore bool
	)

	flag.StringArrayVarP(&denyPatterns, "deny", "d", nil, "Add a deny pattern (can be repeated)")
	flag.StringArrayVarP(&extraFiles, "file", "f", nil, "Additional ignore file (can be repeated)")
	flag.StringVarP(&root, "root", "r", "", "Project root (default: current directory)")
	flag.BoolVarP(&verbose, "verbose", "v", false, "Print loaded ignore files and generated sandbox profile details to stderr")
	flag.BoolVarP(&dryRun, "dry-run", "n", false, "Print profile without executing")
	flag.BoolVar(&denyWrite, "deny-write", false, "Deny all writes outside project root and temp dirs")
	flag.BoolVar(&denyNet, "deny-net", false, "Deny network access (localhost still allowed)")
	flag.BoolVar(&noAutoIgnore, "no-auto-ignore", false, "Disable automatic loading of supported ignore files from the project root")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sbox [options] [--] <command> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Sandbox a command using deny rules from supported ignore files.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() == 0 && !dryRun {
		flag.Usage()
		os.Exit(1)
	}

	sbpl, loadedFiles, err := buildProfile(root, !noAutoIgnore, extraFiles, denyPatterns, denyWrite, denyNet)
	if err != nil {
		fatal("%v", err)
	}

	if verbose {
		writeLoadedFiles(os.Stderr, loadedFiles)
		if !dryRun {
			fmt.Fprint(os.Stderr, sbpl)
		}
	}

	if dryRun {
		fmt.Print(sbpl)
		return
	}

	// Find sandbox-exec.
	sandboxExec, err := findSandboxExec()
	if err != nil {
		fatal("%v", err)
	}

	// Build argv: sandbox-exec -p <profile> <command> [args...]
	command := flag.Args()
	cmdPath, err := findCommand(command[0])
	if err != nil {
		fatal("%v", err)
	}

	argv := []string{"sandbox-exec", "-p", sbpl, cmdPath}
	argv = append(argv, command[1:]...)

	if err := syscall.Exec(sandboxExec, argv, os.Environ()); err != nil {
		fatal("exec sandbox-exec: %v", err)
	}
}

func buildProfile(root string, autoIgnore bool, extraFiles []string, denyPatterns []string, denyWrite bool, denyNet bool) (string, []string, error) {
	projectRoot, err := resolveRoot(root)
	if err != nil {
		return "", nil, fmt.Errorf("resolve root: %w", err)
	}

	inputs, err := collectPatternInputs(projectRoot, autoIgnore, extraFiles, denyPatterns)
	if err != nil {
		return "", nil, err
	}

	if len(inputs.Patterns) == 0 && len(inputs.AbsPaths) == 0 && !denyWrite && !denyNet {
		return "", nil, fmt.Errorf("no patterns specified: create a supported ignore file in the project root, pass an ignore file with -f flag or use -d flags")
	}

	realRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		return "", nil, fmt.Errorf("resolve symlinks for root: %w", err)
	}

	sbpl, err := profile.Generate(inputs.Patterns, inputs.AbsPaths, profile.Options{
		Root:      realRoot,
		DenyWrite: denyWrite,
		DenyNet:   denyNet,
	})
	if err != nil {
		return "", nil, fmt.Errorf("generate profile: %w", err)
	}

	return sbpl, inputs.LoadedFiles, nil
}

func collectPatternInputs(projectRoot string, autoIgnore bool, extraFiles []string, denyPatterns []string) (patternInputs, error) {
	var inputs patternInputs

	if autoIgnore {
		for _, name := range autoIgnoreFiles {
			path := filepath.Join(projectRoot, name)
			lines, found, err := readPatterns(path)
			if err != nil {
				return patternInputs{}, fmt.Errorf("read %s: %w", path, err)
			}
			if found {
				inputs.LoadedFiles = append(inputs.LoadedFiles, path)
			}
			inputs.Patterns = append(inputs.Patterns, lines...)
		}
	}

	for _, f := range extraFiles {
		lines, found, err := readPatterns(f)
		if err != nil {
			return patternInputs{}, fmt.Errorf("read %s: %w", f, err)
		}
		if found {
			inputs.LoadedFiles = append(inputs.LoadedFiles, f)
		}
		inputs.Patterns = append(inputs.Patterns, lines...)
	}

	for _, d := range denyPatterns {
		if isAbsolutePath(d) {
			negate := false
			p := d
			if strings.HasPrefix(p, "!") {
				negate = true
				p = p[1:]
			}
			// Defense-in-depth: SBPL subpath filters are literal, so a rule
			// like (subpath "/**/foo*") is a silent no-op. isAbsolutePath
			// already routes glob patterns to the compiler, but assert it
			// here so future regressions surface as errors instead of
			// silently producing unmatchable rules.
			if strings.ContainsAny(p, "*?[") {
				return patternInputs{}, fmt.Errorf("internal: absolute deny path %q contains glob metacharacters", d)
			}
			inputs.AbsPaths = append(inputs.AbsPaths, profile.AbsPath{
				Path:   resolveAbsoluteDenyPath(expandHome(p)),
				Negate: negate,
			})
			continue
		}

		// Absolute path with glob metacharacters: route through the
		// gitignore compiler but anchor at the filesystem root, so a
		// leading "/path/with/*.glob" means the actual filesystem location
		// regardless of --root. Without Absolute=true, the compiler would
		// re-anchor the pattern under opts.Root and produce a useless
		// regex like ^<root>/path/with/.glob.
		negated := strings.HasPrefix(d, "!")
		body := strings.TrimPrefix(d, "!")
		if strings.HasPrefix(body, "/") || strings.HasPrefix(body, "~/") {
			value := expandHome(body)
			if negated {
				value = "!" + value
			}
			inputs.Patterns = append(inputs.Patterns, profile.Pattern{
				Value:    value,
				Source:   "--deny",
				Absolute: true,
			})
			continue
		}

		inputs.Patterns = append(inputs.Patterns, profile.Pattern{
			Value:  d,
			Source: "--deny",
		})
	}

	return inputs, nil
}

// readPatterns reads non-empty lines from a file.
// Returns found=false if the file doesn't exist.
func readPatterns(path string) ([]profile.Pattern, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()

	var patterns []profile.Pattern
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if line := scanner.Text(); line != "" {
			patterns = append(patterns, profile.Pattern{
				Value:  line,
				Source: path,
				Line:   lineNo,
			})
		}
	}
	return patterns, true, scanner.Err()
}

func writeLoadedFiles(w io.Writer, loadedFiles []string) {
	if len(loadedFiles) == 0 {
		return
	}
	fmt.Fprintln(w, "sbox: loaded ignore files:")
	for _, path := range loadedFiles {
		fmt.Fprintf(w, "  %s\n", path)
	}
}

func resolveRoot(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	return os.Getwd()
}

func findSandboxExec() (string, error) {
	path := "/usr/bin/sandbox-exec"
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("sandbox-exec not found at %s (are you on macOS?)", path)
	}
	return path, nil
}

func findCommand(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("command not found: %s", name)
	}
	return path, nil
}

func isAbsolutePath(pattern string) bool {
	p := strings.TrimPrefix(pattern, "!")
	if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "~/") {
		return false
	}
	// Glob metacharacters need the gitignore compiler — SBPL subpath filters
	// are literal, so a rule like (subpath "/**/foo*") matches nothing. Route
	// these patterns through compilePattern instead of treating them as
	// literal absolute paths.
	return !strings.ContainsAny(p, "*?[")
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func resolveAbsoluteDenyPath(path string) string {
	cleaned := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved
	}

	current := cleaned
	var suffix []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err == nil {
				for i := len(suffix) - 1; i >= 0; i-- {
					resolved = filepath.Join(resolved, suffix[i])
				}
				return resolved
			}
			break
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}

		suffix = append(suffix, filepath.Base(current))
		current = parent
	}

	return cleaned
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sbox: "+format+"\n", args...)
	os.Exit(1)
}
