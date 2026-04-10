// Package profile generates macOS sandbox-exec (SBPL) profiles.
package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pattern is a single ignore rule plus optional source metadata for diagnostics.
type Pattern struct {
	Value  string
	Source string
	Line   int
	// Absolute, when true, compiles this pattern against the filesystem
	// root ("/") rather than opts.Root. Used for CLI -d values that are
	// absolute paths containing glob metacharacters: a leading "/" in such
	// a value means the actual filesystem location, not a project-root
	// anchor.
	Absolute bool
}

// Options controls profile generation.
type Options struct {
	// Root is the resolved (realpath) project root directory.
	Root string
	// DenyWrite denies writes outside the project root and temp dirs.
	DenyWrite bool
	// DenyNet denies outbound network access. Localhost is always allowed.
	DenyNet bool
}

// AbsPath represents an absolute filesystem path to deny (from -d /path or -d ~/path).
type AbsPath struct {
	Path   string
	Negate bool
}

type compiledPattern struct {
	Regex         string
	ExactRegex    string
	Negate        bool
	Anchored      bool
	DirectoryOnly bool
}

// Generate produces an SBPL profile string.
// patterns are gitignore-format lines, scoped to the project root.
// absPaths are absolute filesystem paths to deny.
func Generate(patterns []Pattern, absPaths []AbsPath, opts Options) (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")

	for _, pattern := range patterns {
		compiled, emitRule, err := compilePattern(pattern.Value)
		if err != nil {
			return "", formatPatternError(pattern, err)
		}
		if !emitRule {
			continue
		}

		action := "deny"
		if compiled.Negate {
			action = "allow"
		}

		root := opts.Root
		if pattern.Absolute {
			root = "/"
		}

		if compiled.DirectoryOnly {
			exact := scopeToRoot(compiled.ExactRegex, root, compiled.Anchored)
			descendants := scopeToRoot(compiled.Regex, root, compiled.Anchored)

			writeRegexRule(&b, action, "file*", exact, true)
			writeRegexRule(&b, action, "file*", descendants, false)
			continue
		}

		regex := scopeToRoot(compiled.Regex, root, compiled.Anchored)

		writeRegexRule(&b, action, "file*", regex, false)
	}

	// Absolute filesystem paths.
	for _, ap := range absPaths {
		action := "deny"
		if ap.Negate {
			action = "allow"
		}
		writeRule(&b, action, "file*", subpathFilter(ap.Path))
	}

	if opts.DenyWrite {
		writeDenyWrite(&b, opts.Root)
	}

	if opts.DenyNet {
		writeDenyNet(&b)
	}

	return b.String(), nil
}

const anchoredPrefix = "^(|/)"
const (
	characterClassPlaceholder = "__SBOX_CHARACTER_CLASS_%d__"
	escapedLiteralPlaceholder = "__SBOX_ESCAPED_LITERAL_%d__"
	doubleStarPlaceholder     = "__SBOX_DOUBLE_STAR__"
)

var (
	reSlashDoubleStarSlash = regexp.MustCompile(`/\*\*/`)
	reDoubleStarSlash      = regexp.MustCompile(`\*\*/`)
	reSlashDoubleStar      = regexp.MustCompile(`/\*\*`)
	reSingleStar           = regexp.MustCompile(`\*`)
)

func scopeToRoot(regex string, root string, anchored bool) string {
	if root == "" {
		return regex
	}

	prefix := "^" + escapeRegexLiteral(root)
	if root != "/" {
		prefix += "/"
	}
	if anchored && strings.HasPrefix(regex, anchoredPrefix) {
		return prefix + regex[len(anchoredPrefix):]
	}
	if strings.HasPrefix(regex, "^") {
		return prefix + regex[1:]
	}
	return prefix + regex
}

// compilePattern converts a gitignore pattern line to a POSIX extended regex.
// It returns emitRule=false for blank lines, comments, and other no-op rules.
// Adapted from github.com/sabhiram/go-gitignore (MIT license).
func compilePattern(line string) (compiledPattern, bool, error) {
	// Convert "./" prefix to "/" (anchored to project root).
	for strings.HasPrefix(line, "./") {
		line = "/" + line[2:]
	}

	line = strings.TrimRight(line, "\r")
	line = trimUnescapedTrailingSpaces(line)
	if line == "" {
		return compiledPattern{}, false, nil
	}
	if strings.HasPrefix(line, `#`) {
		return compiledPattern{}, false, nil
	}

	if line == "/" {
		return compiledPattern{}, false, nil
	}

	compiled := compiledPattern{}
	if line[0] == '!' {
		compiled.Negate = true
		line = line[1:]
	}

	compiled.Anchored = isRootRelativePattern(line)
	compiled.DirectoryOnly = strings.HasSuffix(line, "/")
	line = strings.TrimSuffix(line, "/")
	if line == "" {
		return compiledPattern{}, false, nil
	}

	var classes []string
	line, classes, err := protectCharacterClasses(line)
	if err != nil {
		return compiledPattern{}, false, err
	}
	var literals []string
	line, literals = protectEscapedLiterals(line)
	line = escapeRegex(line)

	// Handle "/**/" usage
	if strings.HasPrefix(line, "/**/") {
		line = line[1:]
	}
	line = reSlashDoubleStarSlash.ReplaceAllString(line, `(/|/.+/)`)
	line = reDoubleStarSlash.ReplaceAllString(line, `(|.`+doubleStarPlaceholder+`/)`)
	line = reSlashDoubleStar.ReplaceAllString(line, `(|/.`+doubleStarPlaceholder+`)`)

	// Handle escaping the "*" char
	line = reSingleStar.ReplaceAllString(line, `([^/]*)`)

	// Handle escaping the "?" char before expanding wildcard usage.
	line = strings.ReplaceAll(line, "?", `[^/]`)

	line = strings.ReplaceAll(line, doubleStarPlaceholder, "*")
	line = restoreCharacterClasses(line, classes)
	line = restoreEscapedLiterals(line, literals)

	if compiled.DirectoryOnly {
		compiled.ExactRegex = buildExpression(line, compiled.Anchored, "$")
		compiled.Regex = buildExpression(line, compiled.Anchored, `/.*$`)
		return compiled, true, nil
	}

	compiled.Regex = buildExpression(line, compiled.Anchored, "(|/.*)$")
	return compiled, true, nil
}

func writeDenyWrite(b *strings.Builder, root string) {
	b.WriteString("\n;; deny writes outside project root and temp dirs\n")
	b.WriteString("(deny file-write*\n")
	b.WriteString("  (require-all\n")
	for _, allowed := range denyWriteExceptions(root) {
		fmt.Fprintf(b, "    (require-not %s)\n", subpathFilter(allowed))
	}
	b.WriteString("  )\n")
	b.WriteString(")\n")
}

func writeDenyNet(b *strings.Builder) {
	b.WriteString("\n;; deny non-loopback network access (localhost allowed)\n")
	b.WriteString("(deny network*)\n")
	b.WriteString("(allow network-bind (local ip \"localhost:*\"))\n")
	b.WriteString("(allow network-inbound (local ip \"localhost:*\"))\n")
	b.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
}

func protectEscapedLiterals(line string) (string, []string) {
	var b strings.Builder
	var literals []string

	for i := 0; i < len(line); i++ {
		if line[i] != '\\' || i+1 >= len(line) {
			b.WriteByte(line[i])
			continue
		}

		placeholder := fmt.Sprintf(escapedLiteralPlaceholder, len(literals))
		literals = append(literals, regexp.QuoteMeta(string(line[i+1])))
		b.WriteString(placeholder)
		i++
	}

	return b.String(), literals
}

func restoreEscapedLiterals(line string, literals []string) string {
	for i, literal := range literals {
		line = strings.ReplaceAll(line, fmt.Sprintf(escapedLiteralPlaceholder, i), literal)
	}
	return line
}

func trimUnescapedTrailingSpaces(line string) string {
	end := len(line)
	for end > 0 && line[end-1] == ' ' {
		backslashes := 0
		for i := end - 2; i >= 0 && line[i] == '\\'; i-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			break
		}
		end--
	}
	return line[:end]
}

func isRootRelativePattern(line string) bool {
	if strings.HasPrefix(line, "/") {
		return true
	}

	trimmed := strings.TrimSuffix(line, "/")
	return strings.Contains(trimmed, "/") && !strings.HasPrefix(trimmed, "**/")
}

func protectCharacterClasses(line string) (string, []string, error) {
	var b strings.Builder
	var classes []string

	for i := 0; i < len(line); {
		if line[i] == '\\' && i+1 < len(line) {
			b.WriteByte(line[i])
			b.WriteByte(line[i+1])
			i += 2
			continue
		}

		if line[i] != '[' {
			b.WriteByte(line[i])
			i++
			continue
		}

		class, next, err := parseCharacterClass(line, i)
		if err != nil {
			return "", nil, err
		}

		placeholder := fmt.Sprintf(characterClassPlaceholder, len(classes))
		classes = append(classes, class)
		b.WriteString(placeholder)
		i = next
	}

	return b.String(), classes, nil
}

func restoreCharacterClasses(line string, classes []string) string {
	for i, class := range classes {
		line = strings.ReplaceAll(line, fmt.Sprintf(characterClassPlaceholder, i), class)
	}
	return line
}

func parseCharacterClass(line string, start int) (string, int, error) {
	i := start + 1
	negate := false
	if i < len(line) && (line[i] == '!' || line[i] == '^') {
		negate = true
		i++
	}

	var content strings.Builder
	hasContent := false

	if i < len(line) && (line[i] == ']' || line[i] == '-') {
		writeRegexClassChar(&content, line[i], true)
		hasContent = true
		i++
	}

	for i < len(line) {
		ch := line[i]

		if ch == ']' {
			if !hasContent {
				return "", 0, fmt.Errorf("invalid pattern %q: empty character class", line)
			}

			if negate {
				content.WriteString("/")
			}

			var class strings.Builder
			class.WriteByte('[')
			if negate {
				class.WriteByte('^')
			}
			class.WriteString(content.String())
			class.WriteByte(']')
			return class.String(), i + 1, nil
		}

		if ch == '/' {
			return "", 0, fmt.Errorf("invalid pattern %q: '/' is not allowed inside a character class", line)
		}

		if ch == '\\' {
			if i+1 >= len(line) {
				return "", 0, fmt.Errorf("invalid pattern %q: unterminated escape in character class", line)
			}

			writeRegexClassChar(&content, line[i+1], true)
			hasContent = true
			i += 2
			continue
		}

		literal := false
		if ch == '-' && (i+1 == len(line) || line[i+1] == ']') {
			literal = true
		}
		if ch == '^' && !hasContent && !negate {
			literal = true
		}

		writeRegexClassChar(&content, ch, literal)
		hasContent = true
		i++
	}

	return "", 0, fmt.Errorf("invalid pattern %q: unterminated character class", line)
}

func writeRegexClassChar(b *strings.Builder, ch byte, literal bool) {
	switch ch {
	case '\\', '[', ']', '^':
		b.WriteByte('\\')
		b.WriteByte(ch)
	case '-':
		if literal {
			b.WriteString(`\-`)
			return
		}
		b.WriteByte('-')
	default:
		b.WriteByte(ch)
	}
}

func buildExpression(line string, anchored bool, suffix string) string {
	expr := line + suffix
	if strings.HasPrefix(expr, "/") {
		return "^(|/)" + expr[1:]
	}
	if anchored {
		return "^(|/)" + expr
	}
	return "^(|.*/)" + expr
}

func denyWriteExceptions(root string) []string {
	seen := make(map[string]struct{})
	var paths []string

	add := func(path string) {
		if path == "" {
			return
		}
		path = resolvePath(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	add(root)
	add(os.TempDir())

	return paths
}

func resolvePath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}
	return path
}

func writeRegexRule(b *strings.Builder, action string, operation string, regex string, directoryOnly bool) {
	var filters []string
	if directoryOnly {
		filters = append(filters, "(vnode-type DIRECTORY)")
	}
	filters = append(filters, regexFilter(regex))
	writeRule(b, action, operation, filters...)
}

func writeRule(b *strings.Builder, action string, operation string, filters ...string) {
	if len(filters) == 1 {
		fmt.Fprintf(b, "(%s %s %s)\n", action, operation, filters[0])
		return
	}
	fmt.Fprintf(b, "(%s %s (require-all %s))\n", action, operation, strings.Join(filters, " "))
}

func subpathFilter(path string) string {
	return fmt.Sprintf("(subpath \"%s\")", escapeSBPLString(path))
}

func regexFilter(regex string) string {
	return fmt.Sprintf("(regex \"%s\")", escapeSBPLString(regex))
}

func escapeSBPLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func formatPatternError(pattern Pattern, err error) error {
	if pattern.Source != "" && pattern.Line > 0 {
		return fmt.Errorf("%s:%d: %w", pattern.Source, pattern.Line, err)
	}
	if pattern.Source != "" {
		return fmt.Errorf("%s: %w", pattern.Source, err)
	}
	return fmt.Errorf("pattern %q: %w", pattern.Value, err)
}

func escapeRegex(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', '+', '(', ')', '{', '}', '|', '^', '$', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func escapeRegexLiteral(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.', '+', '*', '?', '(', ')', '{', '}', '|', '^', '$', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
