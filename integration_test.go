package sbox_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/qweeze/sbox/internal/profile"
)

func requireMacOS(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec only available on macOS")
	}
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}
}

func sandboxRun(t *testing.T, sbpl string, name string, args ...string) (string, error) {
	t.Helper()
	cmdArgs := append([]string{"-p", sbpl, name}, args...)
	cmd := exec.Command("/usr/bin/sandbox-exec", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func sandboxPatterns(values ...string) []profile.Pattern {
	patterns := make([]profile.Pattern, 0, len(values))
	for _, value := range values {
		patterns = append(patterns, profile.Pattern{Value: value})
	}
	return patterns
}

func mustGenerateProfileWithPatterns(t *testing.T, patterns []profile.Pattern, absPaths []profile.AbsPath, opts profile.Options) string {
	t.Helper()

	sbpl, err := profile.Generate(patterns, absPaths, opts)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return sbpl
}

func mustGenerateProfile(t *testing.T, values []string, absPaths []profile.AbsPath, opts profile.Options) string {
	t.Helper()
	return mustGenerateProfileWithPatterns(t, sandboxPatterns(values...), absPaths, opts)
}

type sandboxFixture struct {
	root     string
	realRoot string
}

func newSandboxFixture(t *testing.T) sandboxFixture {
	t.Helper()
	return newSandboxFixtureAt(t, t.TempDir())
}

func newSandboxFixtureAt(t *testing.T, root string) sandboxFixture {
	t.Helper()

	realRoot := resolveRealPath(root)
	return sandboxFixture{
		root:     root,
		realRoot: realRoot,
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, contents string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func resolveRealPath(path string) string {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return realPath
}

func (f sandboxFixture) path(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(f.root, rel)
}

func (f sandboxFixture) realPath(rel string) string {
	return resolveRealPath(f.path(rel))
}

type sandboxProbe struct {
	name         string
	command      string
	target       string
	absolute     bool
	wantReadable bool
	wantOutput   string
	wantContains string
}

func runSandboxProbe(t *testing.T, sbpl string, fixture sandboxFixture, probe sandboxProbe) {
	t.Helper()

	command := probe.command
	if command == "" {
		command = "/bin/cat"
	}

	target := probe.target
	if probe.absolute {
		target = resolveRealPath(target)
	} else {
		target = fixture.realPath(probe.target)
	}

	label := probe.name
	if label == "" {
		label = probe.target
	}

	out, err := sandboxRun(t, sbpl, command, target)
	if !probe.wantReadable {
		if err == nil {
			t.Errorf("expected %s to be denied", label)
		}
		return
	}

	if err != nil {
		t.Errorf("expected %s to be allowed: %v, output: %s", label, err, out)
		return
	}

	if probe.wantOutput != "" && strings.TrimSpace(out) != probe.wantOutput {
		t.Errorf("expected %s output %q, got %q", label, probe.wantOutput, strings.TrimSpace(out))
	}
	if probe.wantContains != "" && !strings.Contains(out, probe.wantContains) {
		t.Errorf("expected %s output to contain %q, got %q", label, probe.wantContains, out)
	}
}

type sandboxReadCase struct {
	name    string
	prepare func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe)
}

// TestSandboxReadCases keeps the read-access matrix compact. Write, network,
// and process behavior remain in focused tests below.
func TestSandboxReadCases(t *testing.T) {
	requireMacOS(t)

	cases := []sandboxReadCase{
		{
			name: "exact file",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path(".env"), "SECRET=hunter2")
				mustWriteFile(t, fixture.path("readme.txt"), "hello")

				return fixture, sandboxPatterns(".env"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
					{name: "readme.txt", target: "readme.txt", wantReadable: true, wantOutput: "hello"},
				}
			},
		},
		{
			name: "readme quick start patterns",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("app/.env"), "nested-secret")
				mustWriteFile(t, fixture.path("app/.env.local"), "local-secret")
				mustWriteFile(t, fixture.path("certs/id.pem"), "pem")
				mustWriteFile(t, fixture.path("nested/secrets/token.txt"), "token")
				mustWriteFile(t, fixture.path("notes.txt"), "hello")

				return fixture, sandboxPatterns(".env", ".env.*", "*.pem", "secrets/"), nil, profile.Options{}, []sandboxProbe{
					{name: "app/.env", target: "app/.env", wantReadable: false},
					{name: "app/.env.local", target: "app/.env.local", wantReadable: false},
					{name: "certs/id.pem", target: "certs/id.pem", wantReadable: false},
					{name: "nested/secrets/token.txt", target: "nested/secrets/token.txt", wantReadable: false},
					{name: "notes.txt", target: "notes.txt", wantReadable: true, wantOutput: "hello"},
				}
			},
		},
		{
			name: "glob",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				for _, name := range []string{".env", ".env.local", ".env.production"} {
					mustWriteFile(t, fixture.path(name), "secret")
				}
				mustWriteFile(t, fixture.path("app.js"), "code")

				return fixture, sandboxPatterns(".env", ".env.*"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
					{name: ".env.local", target: ".env.local", wantReadable: false},
					{name: ".env.production", target: ".env.production", wantReadable: false},
					{name: "app.js", target: "app.js", wantReadable: true, wantOutput: "code"},
				}
			},
		},
		{
			name: "readme key glob",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("private.key"), "root-key")
				mustWriteFile(t, fixture.path("nested/private.key"), "nested-key")
				mustWriteFile(t, fixture.path("private.key.bak"), "backup")
				mustWriteFile(t, fixture.path("public.txt"), "public")

				return fixture, sandboxPatterns("*.key"), nil, profile.Options{}, []sandboxProbe{
					{name: "private.key", target: "private.key", wantReadable: false},
					{name: "nested/private.key", target: "nested/private.key", wantReadable: false},
					{name: "private.key.bak", target: "private.key.bak", wantReadable: true, wantOutput: "backup"},
					{name: "public.txt", target: "public.txt", wantReadable: true, wantOutput: "public"},
				}
			},
		},
		{
			name: "question wildcard",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("key1.pem"), "secret")
				mustWriteFile(t, fixture.path("key12.pem"), "public")

				return fixture, sandboxPatterns("key?.pem"), nil, profile.Options{}, []sandboxProbe{
					{name: "key1.pem", target: "key1.pem", wantReadable: false},
					{name: "key12.pem", target: "key12.pem", wantReadable: true, wantOutput: "public"},
				}
			},
		},
		{
			name: "character class",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("a.txt"), "secret-a")
				mustWriteFile(t, fixture.path("b.txt"), "secret-b")
				mustWriteFile(t, fixture.path("c.txt"), "public")

				return fixture, sandboxPatterns("[ab].txt"), nil, profile.Options{}, []sandboxProbe{
					{name: "a.txt", target: "a.txt", wantReadable: false},
					{name: "b.txt", target: "b.txt", wantReadable: false},
					{name: "c.txt", target: "c.txt", wantReadable: true, wantOutput: "public"},
				}
			},
		},
		{
			name: "character class range",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("a.txt"), "secret-a")
				mustWriteFile(t, fixture.path("b.txt"), "secret-b")
				mustWriteFile(t, fixture.path("c.txt"), "secret-c")
				mustWriteFile(t, fixture.path("d.txt"), "public")

				return fixture, sandboxPatterns("[a-c].txt"), nil, profile.Options{}, []sandboxProbe{
					{name: "a.txt", target: "a.txt", wantReadable: false},
					{name: "b.txt", target: "b.txt", wantReadable: false},
					{name: "c.txt", target: "c.txt", wantReadable: false},
					{name: "d.txt", target: "d.txt", wantReadable: true, wantOutput: "public"},
				}
			},
		},
		{
			name: "negated character class range",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("a.txt"), "public-a")
				mustWriteFile(t, fixture.path("c.txt"), "public-c")
				mustWriteFile(t, fixture.path("d.txt"), "secret-d")

				return fixture, sandboxPatterns("[!a-c].txt"), nil, profile.Options{}, []sandboxProbe{
					{name: "a.txt", target: "a.txt", wantReadable: true, wantOutput: "public-a"},
					{name: "c.txt", target: "c.txt", wantReadable: true, wantOutput: "public-c"},
					{name: "d.txt", target: "d.txt", wantReadable: false},
				}
			},
		},
		{
			name: "directory deny",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("secrets/key.pem"), "privkey")

				return fixture, sandboxPatterns("secrets/"), nil, profile.Options{}, []sandboxProbe{
					{name: "secrets/key.pem", target: "secrets/key.pem", wantReadable: false},
					{name: "secrets/", command: "/bin/ls", target: "secrets", wantReadable: false},
				}
			},
		},
		{
			name: "directory pattern skips file",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("secrets"), "plain")
				mustWriteFile(t, fixture.path("nested/secrets/key.pem"), "privkey")

				return fixture, sandboxPatterns("secrets/"), nil, profile.Options{}, []sandboxProbe{
					{name: "plain secrets file", target: "secrets", wantReadable: true, wantOutput: "plain"},
					{name: "nested secrets directory", target: "nested/secrets/key.pem", wantReadable: false},
				}
			},
		},
		{
			name: "lone negation is noop",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path(".env.example"), "template")
				mustWriteFile(t, fixture.path("readme.txt"), "hello")

				return fixture, sandboxPatterns("!.env.example"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env.example", target: ".env.example", wantReadable: true, wantOutput: "template"},
					{name: "readme.txt", target: "readme.txt", wantReadable: true, wantOutput: "hello"},
				}
			},
		},
		{
			name: "negation",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path(".env"), "secret")
				mustWriteFile(t, fixture.path(".env.example"), "template")

				return fixture, sandboxPatterns(".env", ".env.*", "!.env.example"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
					{name: ".env.example", target: ".env.example", wantReadable: true, wantOutput: "template"},
				}
			},
		},
		{
			name: "last match wins",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path(".env"), "secret")

				return fixture, sandboxPatterns(".env", "!.env", ".env"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
				}
			},
		},
		{
			name: "anchored path",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("config/prod.yml"), "prod")
				mustWriteFile(t, fixture.path("config/dev.yml"), "dev")

				return fixture, sandboxPatterns("/config/prod.yml"), nil, profile.Options{}, []sandboxProbe{
					{name: "config/prod.yml", target: "config/prod.yml", wantReadable: false},
					{name: "config/dev.yml", target: "config/dev.yml", wantReadable: true, wantOutput: "dev"},
				}
			},
		},
		{
			name: "readme anchored path",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("config/production.yml"), "prod")
				mustWriteFile(t, fixture.path("other/config/production.yml"), "nested")
				mustWriteFile(t, fixture.path("config/staging.yml"), "staging")

				return fixture, sandboxPatterns("/config/production.yml"), nil, profile.Options{}, []sandboxProbe{
					{name: "config/production.yml", target: "config/production.yml", wantReadable: false},
					{name: "other/config/production.yml", target: "other/config/production.yml", wantReadable: true, wantOutput: "nested"},
					{name: "config/staging.yml", target: "config/staging.yml", wantReadable: true, wantOutput: "staging"},
				}
			},
		},
		{
			name: "absolute glob ignores project root",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				secretDir := t.TempDir()
				realSecretDir := resolveRealPath(secretDir)
				mustWriteFile(t, filepath.Join(secretDir, "leaked.txt"), "secret")
				mustWriteFile(t, filepath.Join(secretDir, "code.go"), "package main\n")

				projectDir := t.TempDir()
				fixture := newSandboxFixtureAt(t, projectDir)

				patterns := []profile.Pattern{
					{Value: filepath.Join(realSecretDir, "*.txt"), Absolute: true},
				}

				return fixture, patterns, nil, profile.Options{}, []sandboxProbe{
					{name: "leaked.txt", target: filepath.Join(secretDir, "leaked.txt"), absolute: true, wantReadable: false},
					{name: "code.go", target: filepath.Join(secretDir, "code.go"), absolute: true, wantReadable: true, wantOutput: "package main"},
				}
			},
		},
		{
			name: "readme double star",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("credentials.json"), "root-creds")
				mustWriteFile(t, fixture.path("nested/credentials.json"), "nested-creds")
				mustWriteFile(t, fixture.path("nested/deeper/credentials.json"), "deep-creds")
				mustWriteFile(t, fixture.path("nested/credentials.txt"), "not-json")

				return fixture, sandboxPatterns("**/credentials.json"), nil, profile.Options{}, []sandboxProbe{
					{name: "credentials.json", target: "credentials.json", wantReadable: false},
					{name: "nested/credentials.json", target: "nested/credentials.json", wantReadable: false},
					{name: "nested/deeper/credentials.json", target: "nested/deeper/credentials.json", wantReadable: false},
					{name: "nested/credentials.txt", target: "nested/credentials.txt", wantReadable: true, wantOutput: "not-json"},
				}
			},
		},
		{
			name: "root double star",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("README.md"), "# top")
				mustWriteFile(t, fixture.path("sub/README.txt"), "# sub")
				mustWriteFile(t, fixture.path("code.go"), "package main\n")

				return fixture, sandboxPatterns("/**/README*"), nil, profile.Options{}, []sandboxProbe{
					{name: "README.md", target: "README.md", wantReadable: false},
					{name: "sub/README.txt", target: "sub/README.txt", wantReadable: false},
					{name: "code.go", target: "code.go", wantReadable: true, wantOutput: "package main"},
				}
			},
		},
		{
			name: "dot slash anchor",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("secret.txt"), "secret")

				return fixture, sandboxPatterns("./*"), nil, profile.Options{}, []sandboxProbe{
					{name: "secret.txt", target: "secret.txt", wantReadable: false},
					{name: "/etc/hosts", target: "/etc/hosts", absolute: true, wantReadable: true},
				}
			},
		},
		{
			name: "project scoped",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)

				return fixture, sandboxPatterns("*"), nil, profile.Options{}, []sandboxProbe{
					{name: "/etc/hosts", target: "/etc/hosts", absolute: true, wantReadable: true},
				}
			},
		},
		{
			name: "filesystem root",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path(".env"), "secret")
				mustWriteFile(t, fixture.path("readme.txt"), "hello")

				return fixture, sandboxPatterns(".env"), nil, profile.Options{Root: "/"}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
					{name: "readme.txt", target: "readme.txt", wantReadable: true, wantOutput: "hello"},
				}
			},
		},
		{
			name: "allowlist traversal",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				mustWriteFile(t, fixture.path("src/main.go"), "package main\n")
				mustWriteFile(t, fixture.path("secret.txt"), "secret")

				return fixture, sandboxPatterns("*", "!src/", "!src/main.go"), nil, profile.Options{}, []sandboxProbe{
					{name: "project root listing", command: "/bin/ls", target: ".", wantReadable: true, wantContains: "src"},
					{name: "src/main.go", target: "src/main.go", wantReadable: true, wantOutput: "package main"},
					{name: "secret.txt", target: "secret.txt", wantReadable: false},
				}
			},
		},
		{
			name: "absolute path deny",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				fixture := newSandboxFixture(t)
				outsideDir := t.TempDir()
				realOutsideDir := resolveRealPath(outsideDir)
				mustWriteFile(t, filepath.Join(outsideDir, "secret.key"), "key")

				return fixture, nil, []profile.AbsPath{{Path: realOutsideDir}}, profile.Options{}, []sandboxProbe{
					{name: "outside secret.key", target: filepath.Join(outsideDir, "secret.key"), absolute: true, wantReadable: false},
				}
			},
		},
		{
			name: "quoted root",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				base := t.TempDir()
				projectDir := filepath.Join(base, `quoted"project`)
				mustMkdirAll(t, projectDir)

				fixture := newSandboxFixtureAt(t, projectDir)
				mustWriteFile(t, fixture.path("secret.txt"), "secret")

				return fixture, sandboxPatterns("/secret.txt"), nil, profile.Options{}, []sandboxProbe{
					{name: "secret.txt", target: "secret.txt", wantReadable: false},
				}
			},
		},
		{
			name: "metachar root",
			prepare: func(t *testing.T) (sandboxFixture, []profile.Pattern, []profile.AbsPath, profile.Options, []sandboxProbe) {
				base := t.TempDir()
				projectDir := filepath.Join(base, `meta*project?root`)
				mustMkdirAll(t, projectDir)

				fixture := newSandboxFixtureAt(t, projectDir)
				mustWriteFile(t, fixture.path(".env"), "SECRET=hunter2")

				return fixture, sandboxPatterns(".env"), nil, profile.Options{}, []sandboxProbe{
					{name: ".env", target: ".env", wantReadable: false},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture, patterns, absPaths, opts, probes := tc.prepare(t)
			if opts.Root == "" {
				opts.Root = fixture.realRoot
			}

			sbpl := mustGenerateProfileWithPatterns(t, patterns, absPaths, opts)
			for _, probe := range probes {
				runSandboxProbe(t, sbpl, fixture, probe)
			}
		})
	}
}

func TestSandboxSymlinkResolutionBlocksDeniedTargets(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	mustWriteFile(t, fixture.path(".env"), "SECRET=hunter2")
	mustWriteFile(t, fixture.path("secrets/key.pem"), "privkey")

	if err := os.Symlink(".env", fixture.path("visible.env")); err != nil {
		t.Fatalf("symlink visible.env: %v", err)
	}
	if err := os.Symlink("secrets", fixture.path("shortcut")); err != nil {
		t.Fatalf("symlink shortcut: %v", err)
	}

	sbpl := mustGenerateProfile(t, []string{".env", "secrets/"}, nil, profile.Options{Root: fixture.realRoot})

	out, err := sandboxRun(t, sbpl, "/bin/cat", fixture.path("visible.env"))
	if err == nil {
		t.Fatalf("expected symlink to denied file to be blocked, output: %s", out)
	}

	out, err = sandboxRun(t, sbpl, "/bin/cat", fixture.path("shortcut/key.pem"))
	if err == nil {
		t.Fatalf("expected symlink into denied directory to be blocked, output: %s", out)
	}
}

func TestSandboxChildProcessInherits(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	mustWriteFile(t, fixture.path(".env"), "SECRET=hunter2")

	sbpl := mustGenerateProfile(t, []string{".env"}, nil, profile.Options{Root: fixture.realRoot})

	realSecret := fixture.realPath(".env")
	_, err := sandboxRun(t, sbpl, "/bin/bash", "-c", "cat "+realSecret)
	if err == nil {
		t.Error("expected child process to be denied reading .env")
	}
}

func TestSandboxDenyWrite(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	sbpl := mustGenerateProfile(t, nil, nil, profile.Options{
		Root:      fixture.realRoot,
		DenyWrite: true,
	})

	insideFile := filepath.Join(fixture.realRoot, "inside.txt")
	_, err := sandboxRun(t, sbpl, "/bin/bash", "-c", "echo hello > "+insideFile)
	if err != nil {
		t.Errorf("expected write inside project root to succeed: %v", err)
	}

	// A directory under /tmp is outside the typical macOS $TMPDIR
	// (under /var/folders), so it falls outside the deny-write whitelist.
	outsideDir, err := os.MkdirTemp("/tmp", "sbox-deny-write-outside-")
	if err != nil {
		t.Skipf("create outside temp dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)

	realOutside := resolveRealPath(outsideDir)
	realCurrentTemp := resolveRealPath(os.TempDir())
	if strings.HasPrefix(strings.TrimRight(realOutside, "/")+"/", strings.TrimRight(realCurrentTemp, "/")+"/") {
		t.Skip("current temp dir resolves under /tmp; cannot distinguish another temp root here")
	}

	outsideFile := filepath.Join(realOutside, "evil.txt")
	_, err = sandboxRun(t, sbpl, "/bin/bash", "-c", "echo evil > "+outsideFile)
	if err == nil {
		t.Error("expected write outside project root to be denied")
	}
}

func TestSandboxDenyWriteBlocksOtherTempRoots(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	sbpl := mustGenerateProfile(t, nil, nil, profile.Options{
		Root:      fixture.realRoot,
		DenyWrite: true,
	})

	outsideTemp, err := os.MkdirTemp("/tmp", "sbox-outside-temp-")
	if err != nil {
		t.Skipf("create temp dir under /tmp: %v", err)
	}
	defer os.RemoveAll(outsideTemp)

	realOutsideTemp := resolveRealPath(outsideTemp)
	realCurrentTemp := resolveRealPath(os.TempDir())
	currentPrefix := strings.TrimRight(realCurrentTemp, "/") + "/"
	if strings.HasPrefix(strings.TrimRight(realOutsideTemp, "/")+"/", currentPrefix) {
		t.Skip("current temp dir already resolves under /tmp; cannot distinguish another temp root here")
	}

	probe := filepath.Join(realOutsideTemp, "probe.txt")
	_, err = sandboxRun(t, sbpl, "/bin/sh", "-c", `echo blocked > "$1"`, "sh", probe)
	if err == nil {
		t.Fatalf("expected writes outside the current temp dir to be denied: %s", probe)
	}
}

func TestSandboxDenyWritePlusDenyPattern(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	mustWriteFile(t, fixture.path(".env"), "SECRET=hunter2")
	realEnv := fixture.realPath(".env")

	sbpl := mustGenerateProfile(t, []string{".env"}, nil, profile.Options{
		Root:      fixture.realRoot,
		DenyWrite: true,
	})

	_, err := sandboxRun(t, sbpl, "/bin/cat", realEnv)
	if err == nil {
		t.Error("expected .env read to be denied")
	}

	_, err = sandboxRun(t, sbpl, "/bin/bash", "-c", "echo pwned > "+realEnv)
	if err == nil {
		t.Error("expected .env write to be denied")
	}

	okFile := filepath.Join(fixture.realRoot, "ok.txt")
	_, err = sandboxRun(t, sbpl, "/bin/bash", "-c", "echo hello > "+okFile)
	if err != nil {
		t.Errorf("expected regular file write to succeed: %v", err)
	}
}

func TestSandboxDenyNet(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	sbpl := mustGenerateProfile(t, nil, nil, profile.Options{
		Root:    fixture.realRoot,
		DenyNet: true,
	})

	// External network should be denied.
	_, err := sandboxRun(t, sbpl, "/usr/bin/curl", "-s", "--connect-timeout", "2", "http://1.1.1.1")
	if err == nil {
		t.Error("expected external network access to be denied")
	}

	// Localhost should still be allowed.
	// curl to a port with nothing listening gives "connection refused" (exit 7),
	// not "Operation not permitted" from the sandbox.
	out, err := sandboxRun(t, sbpl, "/usr/bin/curl", "-s", "--connect-timeout", "2", "http://127.0.0.1:19291")
	if err != nil {
		if strings.Contains(out, "not permitted") || strings.Contains(out, "Operation not permitted") {
			t.Error("localhost connection was blocked by sandbox; expected it to be allowed")
		}
		// "Connection refused" is expected — nothing is listening.
	}
}

func TestSandboxDenyNetAllowsLoopbackBind(t *testing.T) {
	requireMacOS(t)

	fixture := newSandboxFixture(t)
	sbpl := mustGenerateProfile(t, nil, nil, profile.Options{
		Root:    fixture.realRoot,
		DenyNet: true,
	})

	out, err := sandboxRun(t, sbpl, "/usr/bin/python3", "-c", `import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print("ok")`)
	if err != nil {
		t.Fatalf("expected loopback bind to be allowed: %v, output: %s", err, out)
	}
	if strings.TrimSpace(out) != "ok" {
		t.Fatalf("expected loopback bind probe to print ok, got %q", out)
	}
}
