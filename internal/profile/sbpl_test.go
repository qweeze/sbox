package profile

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	ignore "github.com/sabhiram/go-gitignore"
)

func testPatterns(values ...string) []Pattern {
	patterns := make([]Pattern, 0, len(values))
	for _, value := range values {
		patterns = append(patterns, Pattern{Value: value})
	}
	return patterns
}

// TestCompilePatternMatchesLibrary cross-validates our compilePattern against
// the go-gitignore library's MatchesPath for patterns that the library supports.
func TestCompilePatternMatchesLibrary(t *testing.T) {
	tests := []struct {
		pattern string
		paths   map[string]bool
	}{
		{
			pattern: ".env",
			paths: map[string]bool{
				".env":         true,
				"foo/.env":     true,
				"a/b/.env":     true,
				".env.local":   false,
				".environment": false,
				"env":          false,
				".env/foo":     true,
			},
		},
		{
			pattern: "*.pem",
			paths: map[string]bool{
				"cert.pem":     true,
				"foo/cert.pem": true,
				"a/b/key.pem":  true,
				"cert.pem.bak": false,
				"pem":          false,
			},
		},
		{
			pattern: ".env.*",
			paths: map[string]bool{
				".env.local":      true,
				".env.production": true,
				"foo/.env.local":  true,
				".env":            false,
				".env.local.bak":  true,
			},
		},
		{
			pattern: "secrets/",
			paths: map[string]bool{
				"secrets/key.pem": true,
				"secrets/a/b":     true,
				"foo/secrets/bar": true,
				"secrets":         false,
			},
		},
		{
			pattern: "/config/prod.yml",
			paths: map[string]bool{
				"config/prod.yml":   true,
				"a/config/prod.yml": false,
				"config/dev.yml":    false,
			},
		},
		{
			pattern: "**/credentials.json",
			paths: map[string]bool{
				"credentials.json":     true,
				"foo/credentials.json": true,
				"a/b/credentials.json": true,
			},
		},
		{
			pattern: "a/**/b",
			paths: map[string]bool{
				"a/b":     true,
				"a/x/b":   true,
				"a/x/y/b": true,
			},
		},
		{
			pattern: "*.log",
			paths: map[string]bool{
				"app.log":     true,
				"foo/app.log": true,
				"app.log.bak": false,
				".log":        true,
			},
		},
		{
			pattern: "build/",
			paths: map[string]bool{
				"build/output.js": true,
				"build/a/b":       true,
				"src/build/out":   true,
				"build":           false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			pattern, ok, err := compilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("compilePattern(%q): %v", tt.pattern, err)
			}
			gi := ignore.CompileIgnoreLines(tt.pattern)

			for path, wantMatch := range tt.paths {
				libMatch := gi.MatchesPath(path)

				if !ok {
					if libMatch {
						t.Errorf("path %q: library matches but compilePattern returned !ok", path)
					}
					continue
				}

				compiled := regexp.MustCompile(pattern.Regex)
				ourMatch := compiled.MatchString(path)
				if pattern.Negate {
					ourMatch = false
				}

				if ourMatch != libMatch {
					t.Errorf("path %q: our regex match=%v (regex=%q, negate=%v), library match=%v",
						path, ourMatch, pattern.Regex, pattern.Negate, libMatch)
				}

				if libMatch != wantMatch {
					t.Errorf("path %q: library match=%v, expected=%v (pattern=%q)",
						path, libMatch, wantMatch, tt.pattern)
				}
			}
		})
	}
}

func TestCompilePatternQuestionWildcard(t *testing.T) {
	pattern, ok, err := compilePattern("key?.pem")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}
	if pattern.Negate {
		t.Fatal("compilePattern returned negate=true")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	tests := map[string]bool{
		"key1.pem":     true,
		"foo/keyA.pem": true,
		"key.pem":      false,
		"key12.pem":    false,
	}

	for path, want := range tests {
		if got := compiled.MatchString(path); got != want {
			t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, pattern.Regex)
		}
	}
}

func TestCompilePatternLeadingSpacesBeforeHashAreLiteral(t *testing.T) {
	pattern, ok, err := compilePattern("  # comment")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	if !compiled.MatchString("  # comment") {
		t.Fatalf("pattern should match a literal leading-space filename (regex=%q)", pattern.Regex)
	}
	if compiled.MatchString("# comment") {
		t.Fatalf("pattern should preserve leading spaces (regex=%q)", pattern.Regex)
	}
}

func TestCompilePatternTrimsOnlyUnescapedTrailingSpaces(t *testing.T) {
	pattern, ok, err := compilePattern("foo  ")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	if !compiled.MatchString("foo") {
		t.Fatalf("pattern should ignore unescaped trailing spaces (regex=%q)", pattern.Regex)
	}
	if compiled.MatchString("foo  ") {
		t.Fatalf("pattern should not keep unescaped trailing spaces (regex=%q)", pattern.Regex)
	}
}

func TestCompilePatternPreservesEscapedTrailingSpaces(t *testing.T) {
	pattern, ok, err := compilePattern(`foo\ `)
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	if !compiled.MatchString("foo ") {
		t.Fatalf("pattern should preserve escaped trailing spaces (regex=%q)", pattern.Regex)
	}
	if compiled.MatchString("foo") {
		t.Fatalf("pattern should require the escaped trailing space (regex=%q)", pattern.Regex)
	}
}

func TestCompilePatternEscapesRegexMetacharacters(t *testing.T) {
	tests := []struct {
		pattern string
		match   string
		noMatch string
	}{
		{
			pattern: "foo+bar",
			match:   "foo+bar",
			noMatch: "foooooobar",
		},
		{
			pattern: `file\[1\].txt`,
			match:   "file[1].txt",
			noMatch: "file1.txt",
		},
		{
			pattern: "notes(backup).md",
			match:   "notes(backup).md",
			noMatch: "notesbackup.md",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			pattern, ok, err := compilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("compilePattern returned error: %v", err)
			}
			if !ok {
				t.Fatal("compilePattern returned !ok")
			}
			if pattern.Negate {
				t.Fatal("compilePattern returned negate=true")
			}

			compiled := regexp.MustCompile(pattern.Regex)
			if !compiled.MatchString(tt.match) {
				t.Fatalf("pattern %q should match %q (regex=%q)", tt.pattern, tt.match, pattern.Regex)
			}
			if compiled.MatchString(tt.noMatch) {
				t.Fatalf("pattern %q should not match %q (regex=%q)", tt.pattern, tt.noMatch, pattern.Regex)
			}
		})
	}
}

func TestCompilePatternCharacterClasses(t *testing.T) {
	tests := []struct {
		pattern string
		paths   map[string]bool
	}{
		{
			pattern: "[ab].txt",
			paths: map[string]bool{
				"a.txt":     true,
				"b.txt":     true,
				"c.txt":     false,
				"sub/a.txt": true,
			},
		},
		{
			pattern: "[a-c].txt",
			paths: map[string]bool{
				"a.txt": true,
				"b.txt": true,
				"c.txt": true,
				"d.txt": false,
			},
		},
		{
			pattern: "[!a-c].txt",
			paths: map[string]bool{
				"a.txt": false,
				"c.txt": false,
				"d.txt": true,
				"].txt": true,
			},
		},
		{
			pattern: "[^a].txt",
			paths: map[string]bool{
				"a.txt": false,
				"b.txt": true,
				"^.txt": true,
			},
		},
		{
			pattern: "[]a].txt",
			paths: map[string]bool{
				"a.txt": true,
				"].txt": true,
				"b.txt": false,
			},
		},
		{
			pattern: "[a-].txt",
			paths: map[string]bool{
				"a.txt": true,
				"-.txt": true,
				"b.txt": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			pattern, ok, err := compilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("compilePattern returned error: %v", err)
			}
			if !ok {
				t.Fatal("compilePattern returned !ok")
			}

			compiled := regexp.MustCompile(pattern.Regex)
			for path, want := range tt.paths {
				if got := compiled.MatchString(path); got != want {
					t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, pattern.Regex)
				}
			}
		})
	}
}

func TestCompilePatternRejectsMalformedCharacterClass(t *testing.T) {
	_, _, err := compilePattern("[abc")
	if err == nil {
		t.Fatal("expected malformed character class to be rejected")
	}
	if !strings.Contains(err.Error(), "unterminated character class") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompilePatternMiddleSlashIsRootRelative(t *testing.T) {
	pattern, ok, err := compilePattern("config/prod.yml")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}
	if pattern.Negate {
		t.Fatal("compilePattern returned negate=true")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	tests := map[string]bool{
		"config/prod.yml":   true,
		"a/config/prod.yml": false,
		"config/dev.yml":    false,
	}

	for path, want := range tests {
		if got := compiled.MatchString(path); got != want {
			t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, pattern.Regex)
		}
	}
}

func TestCompilePatternRootSlashDoubleStarMatchesAtAnyDepth(t *testing.T) {
	pattern, ok, err := compilePattern("/**/README*")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}
	if !pattern.Anchored {
		t.Fatal("expected /**/... to be anchored")
	}

	root := "/Users/test/project"
	regex := scopeToRoot(pattern.Regex, root, pattern.Anchored)
	compiled := regexp.MustCompile(regex)

	tests := map[string]bool{
		"/Users/test/project/README.md":         true,
		"/Users/test/project/sub/README.md":     true,
		"/Users/test/project/a/b/README.txt":    true,
		"/Users/test/project/README":            true,
		"/Users/test/project/code.go":           false,
		"/Users/test/other/README.md":           false,
		"/Users/test/project/sub/notreadme.txt": false,
	}
	for path, want := range tests {
		if got := compiled.MatchString(path); got != want {
			t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, regex)
		}
	}
}

func TestCompilePatternAnchoredMiddleSlashDoubleStarMatchesAtAnyDepth(t *testing.T) {
	pattern, ok, err := compilePattern("/path/to/**/file")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}
	if !pattern.Anchored {
		t.Fatal("expected /path/to/**/file to be anchored")
	}

	root := "/Users/test/project"
	regex := scopeToRoot(pattern.Regex, root, pattern.Anchored)
	compiled := regexp.MustCompile(regex)

	tests := map[string]bool{
		"/Users/test/project/path/to/file":        true,
		"/Users/test/project/path/to/nested/file": true,
		"/Users/test/project/path/to/a/b/file":    true,
		"/Users/test/project/other/path/to/file":  false,
		"/Users/test/project/path/to/file.txt":    false,
		"/Users/test/other/path/to/nested/file":   false,
	}
	for path, want := range tests {
		if got := compiled.MatchString(path); got != want {
			t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, regex)
		}
	}
}

func TestCompilePatternSlashDoubleStarIsRootRelative(t *testing.T) {
	pattern, ok, err := compilePattern("logs/**")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern returned !ok")
	}
	if pattern.Negate {
		t.Fatal("compilePattern returned negate=true")
	}

	compiled := regexp.MustCompile(pattern.Regex)
	tests := map[string]bool{
		"logs/app.log":     true,
		"logs/a/b/c.log":   true,
		"foo/logs/app.log": false,
	}

	for path, want := range tests {
		if got := compiled.MatchString(path); got != want {
			t.Errorf("path %q: match=%v, want=%v (regex=%q)", path, got, want, pattern.Regex)
		}
	}
}

func TestScopeToRoot(t *testing.T) {
	root := "/Users/test/project"

	tests := []struct {
		name  string
		regex string
		root  string
		want  string
	}{
		{
			name:  "anchored pattern gets root prefix",
			regex: `^(|/)config/prod\.yml(|/.*)$`,
			root:  root,
			want:  `^/Users/test/project/config/prod\.yml(|/.*)$`,
		},
		{
			name:  "unanchored pattern becomes root scoped",
			regex: `^(|.*/)\.env(|/.*)$`,
			root:  root,
			want:  `^/Users/test/project/(|.*/)\.env(|/.*)$`,
		},
		{
			name:  "root with dots gets escaped",
			regex: `^(|/)foo(|/.*)$`,
			root:  "/Users/test/my.project",
			want:  `^/Users/test/my\.project/foo(|/.*)$`,
		},
		{
			name:  "root with wildcard metacharacters gets escaped",
			regex: `^(|.*/)\.env(|/.*)$`,
			root:  "/Users/test/project*name?",
			want:  `^/Users/test/project\*name\?/(|.*/)\.env(|/.*)$`,
		},
		{
			name:  "filesystem root does not produce double slash",
			regex: `^(|.*/)\.env(|/.*)$`,
			root:  "/",
			want:  `^/(|.*/)\.env(|/.*)$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopeToRoot(tt.regex, tt.root, strings.HasPrefix(tt.regex, anchoredPrefix))
			if got != tt.want {
				t.Errorf("scopeToRoot() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnchoredPatternMatchesAbsolutePath(t *testing.T) {
	root := "/Users/test/project"

	pattern, ok, err := compilePattern("/config/prod.yml")
	if err != nil {
		t.Fatalf("compilePattern returned error: %v", err)
	}
	if !ok {
		t.Fatal("compilePattern failed")
	}
	regex := scopeToRoot(pattern.Regex, root, pattern.Anchored)
	compiled := regexp.MustCompile(regex)

	if !compiled.MatchString("/Users/test/project/config/prod.yml") {
		t.Error("should match absolute path at root")
	}
	if compiled.MatchString("/Users/test/project/sub/config/prod.yml") {
		t.Error("should NOT match in subdirectory")
	}
	if compiled.MatchString("/other/project/config/prod.yml") {
		t.Error("should NOT match in different root")
	}
}

func TestGenerate(t *testing.T) {
	opts := Options{Root: "/Users/test/project"}
	prof, err := Generate(testPatterns(".env", "*.pem", "!.env.example", "secrets/", "/config/prod.yml"), nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, "(version 1)") {
		t.Error("missing version")
	}
	if !strings.Contains(prof, "(allow default)") {
		t.Error("missing allow default")
	}
	if !strings.Contains(prof, "(deny file*") {
		t.Error("missing deny file rule")
	}
	if !strings.Contains(prof, "(allow file*") {
		t.Error("missing allow file rule for negation")
	}
	// Anchored pattern should have root in regex.
	if !strings.Contains(prof, "/Users/test/project/") {
		t.Errorf("anchored pattern missing root prefix in:\n%s", prof)
	}
}

func TestGenerateProjectScoped(t *testing.T) {
	opts := Options{Root: "/Users/test/project"}
	prof, err := Generate(testPatterns(".env"), nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, `/Users/test/project/(|.*/)\\.env(|/.*)$`) {
		t.Errorf("unanchored pattern should be scoped under the project root:\n%s", prof)
	}
	if strings.Contains(prof, `(subpath "/Users/test/project")`) {
		t.Errorf("unanchored pattern should scope via regex, not a separate subpath filter:\n%s", prof)
	}
}

func TestGenerateAbsolutePatternIgnoresOptsRoot(t *testing.T) {
	patterns := []Pattern{{Value: "/Users/me/secret/*", Absolute: true}}
	prof, err := Generate(patterns, nil, Options{Root: "/Users/test/project"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	// The compiled regex should anchor at the filesystem root, not at
	// /Users/test/project/Users/me/secret/.
	wantRegex := `^/Users/me/secret/([^/]*)(|/.*)$`
	if !strings.Contains(prof, escapeSBPLString(wantRegex)) {
		t.Errorf("absolute pattern should anchor at filesystem root, got profile:\n%s", prof)
	}
	if strings.Contains(prof, "/Users/test/project/Users/me/secret") {
		t.Errorf("absolute pattern should NOT be re-anchored under opts.Root, got profile:\n%s", prof)
	}
}

func TestGenerateAbsPaths(t *testing.T) {
	absPaths := []AbsPath{
		{Path: "/Users/test/.ssh"},
		{Path: "/Users/test/.aws"},
	}
	prof, err := Generate(nil, absPaths, Options{Root: "/Users/test/project"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, `(deny file* (subpath "/Users/test/.ssh"))`) {
		t.Errorf("missing .ssh deny rule in:\n%s", prof)
	}
	if !strings.Contains(prof, `(deny file* (subpath "/Users/test/.aws"))`) {
		t.Errorf("missing .aws deny rule in:\n%s", prof)
	}
}

func TestGenerateDenyWrite(t *testing.T) {
	opts := Options{Root: "/Users/test/project", DenyWrite: true}
	prof, err := Generate(nil, nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, `(require-not (subpath "/Users/test/project"))`) {
		t.Errorf("deny-write missing project root exception in:\n%s", prof)
	}
}

func TestGenerateDenyWriteAllowsCurrentTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	prof, err := Generate(nil, nil, Options{Root: "/Users/test/project", DenyWrite: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	realTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		realTmpDir = tmpDir
	}

	if !strings.Contains(prof, `(require-not (subpath "`+realTmpDir+`"))`) {
		t.Errorf("deny-write missing current temp dir exception in:\n%s", prof)
	}
}

func TestGenerateDenyWriteDoesNotWhitelistGlobalTempRoots(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	prof, err := Generate(nil, nil, Options{Root: "/Users/test/project", DenyWrite: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if strings.Contains(prof, `(require-not (subpath "/private/tmp"))`) {
		t.Errorf("deny-write should not whitelist the global /private/tmp root:\n%s", prof)
	}
	if strings.Contains(prof, `(require-not (subpath "/private/var/folders"))`) {
		t.Errorf("deny-write should not whitelist the global /private/var/folders root:\n%s", prof)
	}
}

func TestGenerateDenyNet(t *testing.T) {
	opts := Options{Root: "/Users/test/project", DenyNet: true}
	prof, err := Generate(nil, nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, "(deny network*)") {
		t.Errorf("missing global network deny in:\n%s", prof)
	}
	if !strings.Contains(prof, `(allow network-bind (local ip "localhost:*"))`) {
		t.Errorf("missing loopback bind allow in:\n%s", prof)
	}
	if !strings.Contains(prof, `(allow network-inbound (local ip "localhost:*"))`) {
		t.Errorf("missing loopback inbound allow in:\n%s", prof)
	}
	if !strings.Contains(prof, `(allow network-outbound (remote ip "localhost:*"))`) {
		t.Errorf("missing localhost allow in:\n%s", prof)
	}
	if strings.Contains(prof, `(allow network-outbound (local ip "localhost:*"))`) {
		t.Errorf("deny-net should not emit a broad local-ip outbound allow:\n%s", prof)
	}

	denyIndex := strings.Index(prof, "(deny network*)")
	allowIndex := strings.Index(prof, `(allow network-bind (local ip "localhost:*"))`)
	if denyIndex == -1 || allowIndex == -1 || allowIndex < denyIndex {
		t.Errorf("loopback allow rules should be emitted after the global deny:\n%s", prof)
	}
}

func TestGenerateDenySpawn(t *testing.T) {
	prof, err := Generate(nil, nil, Options{Root: "/Users/test/project", DenySpawn: true})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	wantRules := []string{
		`(deny mach-lookup (global-name-prefix "com.apple.coreservices."))`,
		`(deny mach-lookup (global-name-prefix "com.apple.lsd."))`,
		`(deny mach-lookup (global-name "com.apple.appleeventsd"))`,
		`(deny appleevent-send)`,
	}
	for _, rule := range wantRules {
		if !strings.Contains(prof, rule) {
			t.Errorf("missing deny-spawn rule %q in:\n%s", rule, prof)
		}
	}
}

func TestGenerateOmitsDenySpawnByDefault(t *testing.T) {
	prof, err := Generate(testPatterns(".env"), nil, Options{Root: "/Users/test/project"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if strings.Contains(prof, "mach-lookup") || strings.Contains(prof, "appleevent-send") {
		t.Errorf("Options{DenySpawn:false} should not emit spawn-deny rules:\n%s", prof)
	}
}

func TestGenerateDotSlashAnchoring(t *testing.T) {
	opts := Options{Root: "/Users/test/project"}
	prof, err := Generate(testPatterns("./*"), nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, "(deny file*") {
		t.Errorf("expected deny rule for ./* pattern in:\n%s", prof)
	}
	if !strings.Contains(prof, "/Users/test/project/") {
		t.Errorf("expected ./* to be anchored to root in:\n%s", prof)
	}
	if strings.Contains(prof, "require-all") {
		t.Errorf("anchored pattern should not use require-all:\n%s", prof)
	}
}

func TestGenerateMiddleSlashPatternAnchoring(t *testing.T) {
	opts := Options{Root: "/Users/test/project"}
	prof, err := Generate(testPatterns("config/prod.yml"), nil, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, "/Users/test/project/config/prod\\\\.yml") {
		t.Errorf("expected middle-slash pattern to be anchored to root in:\n%s", prof)
	}
	if strings.Contains(prof, "require-all") {
		t.Errorf("middle-slash pattern should not use require-all:\n%s", prof)
	}
}

func TestGenerateDirectoryPatternUsesDirectoryVNodeFilter(t *testing.T) {
	prof, err := Generate(testPatterns("secrets/"), nil, Options{Root: "/Users/test/project"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, "(vnode-type DIRECTORY)") {
		t.Fatalf("directory patterns should filter exact-node rules to directories:\n%s", prof)
	}
	if !strings.Contains(prof, `secrets/.*$`) {
		t.Fatalf("directory patterns should still deny descendants:\n%s", prof)
	}
}

func TestGenerateEscapesQuotedPaths(t *testing.T) {
	prof, err := Generate(testPatterns("/config/prod.yml"), nil, Options{Root: `/Users/test/project"quoted`})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, `/Users/test/project\"quoted/config/prod\\.yml`) {
		t.Fatalf("expected quoted root to be escaped in profile:\n%s", prof)
	}
}

func TestGenerateEscapesBackslashInSubpath(t *testing.T) {
	absPaths := []AbsPath{{Path: `/Users/test/weird\path`}}
	prof, err := Generate(nil, absPaths, Options{Root: "/Users/test/project"})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	if !strings.Contains(prof, `(subpath "/Users/test/weird\\path")`) {
		t.Fatalf("expected backslash in subpath to be escaped:\n%s", prof)
	}
}

func TestGenerateRejectsInvalidPatternsWithSource(t *testing.T) {
	_, err := Generate([]Pattern{{
		Value:  "[ab",
		Source: ".aiignore",
		Line:   3,
	}}, nil, Options{Root: "/Users/test/project"})
	if err == nil {
		t.Fatal("expected invalid pattern to fail")
	}
	if !strings.Contains(err.Error(), ".aiignore:3") {
		t.Fatalf("expected source location in error, got: %v", err)
	}
}
