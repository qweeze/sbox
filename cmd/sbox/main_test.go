package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindCommandAllowsRelativeExecutablePaths(t *testing.T) {
	dir := t.TempDir()

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	cases := []string{"./tool", "bin/tool"}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			full := filepath.Join(dir, filepath.Clean(path))
			if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(full, []byte("#!/bin/sh\n"), 0755); err != nil {
				t.Fatalf("write executable: %v", err)
			}

			got, err := findCommand(path)
			if err != nil {
				t.Fatalf("findCommand(%q): %v", path, err)
			}
			if filepath.Clean(got) != filepath.Clean(path) {
				t.Fatalf("findCommand(%q) = %q, want %q", path, got, path)
			}
		})
	}
}

func TestResolveAbsoluteDenyPathFallsBackForFullyMissingPath(t *testing.T) {
	input := "/this/path/does/not/exist"
	got := resolveAbsoluteDenyPath(input)
	if got != filepath.Clean(input) {
		t.Fatalf("resolveAbsoluteDenyPath(%q) = %q, want cleaned input %q", input, got, filepath.Clean(input))
	}
}

func TestResolveAbsoluteDenyPathResolvesExistingParentSymlinks(t *testing.T) {
	base := t.TempDir()
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		realBase = base
	}

	realDir := filepath.Join(realBase, "real")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}

	linkPath := filepath.Join(realBase, "link")
	if err := os.Symlink(realDir, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	got := resolveAbsoluteDenyPath(filepath.Join(linkPath, "future.txt"))
	want := filepath.Join(realDir, "future.txt")
	if got != want {
		t.Fatalf("resolveAbsoluteDenyPath() = %q, want %q", got, want)
	}
}

func TestAutoIgnoreFilesList(t *testing.T) {
	want := []string{
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

	if len(autoIgnoreFiles) != len(want) {
		t.Fatalf("autoIgnoreFiles length = %d, want %d", len(autoIgnoreFiles), len(want))
	}
	for i, wantName := range want {
		if autoIgnoreFiles[i] != wantName {
			t.Fatalf("autoIgnoreFiles[%d] = %q, want %q", i, autoIgnoreFiles[i], wantName)
		}
	}
}

func TestCollectPatternInputsPreservesSourceOrder(t *testing.T) {
	root := t.TempDir()

	aiIgnore := filepath.Join(root, ".aiignore")
	if err := os.WriteFile(aiIgnore, []byte("ai-deny\n"), 0644); err != nil {
		t.Fatalf("write .aiignore: %v", err)
	}

	cursorIgnore := filepath.Join(root, ".cursorignore")
	if err := os.WriteFile(cursorIgnore, []byte("cursor-deny\n"), 0644); err != nil {
		t.Fatalf("write .cursorignore: %v", err)
	}

	extraIgnore := filepath.Join(root, "extra.aiignore")
	if err := os.WriteFile(extraIgnore, []byte("extra-deny\n"), 0644); err != nil {
		t.Fatalf("write extra ignore: %v", err)
	}

	inputs, err := collectPatternInputs(root, true, []string{extraIgnore}, []string{"cli-deny", "!/tmp/allowed"})
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.Patterns) != 4 {
		t.Fatalf("expected 4 scoped patterns, got %d", len(inputs.Patterns))
	}

	wantValues := []string{"ai-deny", "cursor-deny", "extra-deny", "cli-deny"}
	for i, want := range wantValues {
		if inputs.Patterns[i].Value != want {
			t.Fatalf("patterns[%d].Value = %q, want %q", i, inputs.Patterns[i].Value, want)
		}
	}

	if inputs.Patterns[0].Source != aiIgnore || inputs.Patterns[0].Line != 1 {
		t.Fatalf("unexpected source metadata for first pattern: %+v", inputs.Patterns[0])
	}
	if inputs.Patterns[1].Source != cursorIgnore || inputs.Patterns[1].Line != 1 {
		t.Fatalf("unexpected source metadata for second pattern: %+v", inputs.Patterns[1])
	}
	if inputs.Patterns[2].Source != extraIgnore || inputs.Patterns[2].Line != 1 {
		t.Fatalf("unexpected source metadata for third pattern: %+v", inputs.Patterns[2])
	}
	if inputs.Patterns[3].Source != "--deny" || inputs.Patterns[3].Line != 0 {
		t.Fatalf("unexpected source metadata for CLI pattern: %+v", inputs.Patterns[3])
	}

	wantLoadedFiles := []string{aiIgnore, cursorIgnore, extraIgnore}
	if len(inputs.LoadedFiles) != len(wantLoadedFiles) {
		t.Fatalf("expected %d loaded files, got %d", len(wantLoadedFiles), len(inputs.LoadedFiles))
	}
	for i, want := range wantLoadedFiles {
		if inputs.LoadedFiles[i] != want {
			t.Fatalf("loadedFiles[%d] = %q, want %q", i, inputs.LoadedFiles[i], want)
		}
	}

	if len(inputs.AbsPaths) != 1 {
		t.Fatalf("expected 1 absolute path rule, got %d", len(inputs.AbsPaths))
	}
	wantAbsPath := resolveAbsoluteDenyPath("/tmp/allowed")
	if inputs.AbsPaths[0].Path != wantAbsPath {
		t.Fatalf("absPaths[0].Path = %q, want %q", inputs.AbsPaths[0].Path, wantAbsPath)
	}
	if !inputs.AbsPaths[0].Negate {
		t.Fatal("expected absolute path rule to preserve negation")
	}
}

func TestIsAbsolutePathRejectsGlobMetacharacters(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"/Users/me/.ssh", true},
		{"~/.aws", true},
		{"!/Users/me/.ssh", true},
		{"!~/.aws", true},
		{"/**/README*", false},
		{"/foo*", false},
		{"~/foo*", false},
		{"/foo?", false},
		{"/foo[ab]", false},
		{"!/**/README*", false},
		{".env", false},
		{"*.pem", false},
	}

	for _, tc := range cases {
		if got := isAbsolutePath(tc.pattern); got != tc.want {
			t.Errorf("isAbsolutePath(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

func TestCollectPatternInputsMarksAbsoluteGlobPatterns(t *testing.T) {
	root := t.TempDir()

	inputs, err := collectPatternInputs(root, false, nil, []string{"/**/README*", "!/Users/me/secret/*"})
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.AbsPaths) != 0 {
		t.Fatalf("expected glob /-prefixed patterns to skip the absolute-path branch, got %d AbsPaths", len(inputs.AbsPaths))
	}
	if len(inputs.Patterns) != 2 {
		t.Fatalf("expected 2 compiler patterns, got %d", len(inputs.Patterns))
	}

	if inputs.Patterns[0].Value != "/**/README*" || inputs.Patterns[0].Source != "--deny" || !inputs.Patterns[0].Absolute {
		t.Errorf("unexpected first pattern: %+v", inputs.Patterns[0])
	}
	if inputs.Patterns[1].Value != "!/Users/me/secret/*" || inputs.Patterns[1].Source != "--deny" || !inputs.Patterns[1].Absolute {
		t.Errorf("unexpected second pattern: %+v", inputs.Patterns[1])
	}
}

func TestCollectPatternInputsExpandsHomeForAbsoluteGlobPatterns(t *testing.T) {
	root := t.TempDir()

	inputs, err := collectPatternInputs(root, false, nil, []string{"~/foo*", "!~/cache?"})
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.AbsPaths) != 0 {
		t.Fatalf("expected ~/-prefixed glob patterns to skip the absolute-path branch, got %d AbsPaths", len(inputs.AbsPaths))
	}
	if len(inputs.Patterns) != 2 {
		t.Fatalf("expected 2 compiler patterns, got %d", len(inputs.Patterns))
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	wantFirst := filepath.Join(home, "foo*")
	if inputs.Patterns[0].Value != wantFirst || !inputs.Patterns[0].Absolute {
		t.Errorf("first pattern = %+v, want value %q with Absolute=true", inputs.Patterns[0], wantFirst)
	}

	wantSecond := "!" + filepath.Join(home, "cache?")
	if inputs.Patterns[1].Value != wantSecond || !inputs.Patterns[1].Absolute {
		t.Errorf("second pattern = %+v, want value %q with Absolute=true", inputs.Patterns[1], wantSecond)
	}
}

func TestCollectPatternInputsExpandsHomeForAbsoluteCliPaths(t *testing.T) {
	root := t.TempDir()

	inputs, err := collectPatternInputs(root, true, nil, []string{"!~/allowed"})
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.Patterns) != 0 {
		t.Fatalf("expected no scoped patterns, got %d", len(inputs.Patterns))
	}
	if len(inputs.AbsPaths) != 1 {
		t.Fatalf("expected 1 absolute path rule, got %d", len(inputs.AbsPaths))
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	want := filepath.Join(home, "allowed")
	if inputs.AbsPaths[0].Path != want {
		t.Fatalf("absPaths[0].Path = %q, want %q", inputs.AbsPaths[0].Path, want)
	}
	if !inputs.AbsPaths[0].Negate {
		t.Fatal("expected home-expanded absolute path rule to preserve negation")
	}
}

func TestBuildProfileRejectsMissingRestrictions(t *testing.T) {
	root := t.TempDir()

	_, _, err := buildProfile(root, true, nil, nil, false, false)
	if err == nil {
		t.Fatal("expected missing restrictions to fail")
	}
	if !strings.Contains(err.Error(), "no patterns specified") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildProfileAllowsDenyNetWithoutPatterns(t *testing.T) {
	root := t.TempDir()

	prof, _, err := buildProfile(root, true, nil, nil, false, true)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	if !strings.Contains(prof, "(deny network*)") {
		t.Fatalf("expected deny-net profile to contain a global network deny:\n%s", prof)
	}
	if !strings.Contains(prof, `(allow network-bind (local ip "localhost:*"))`) {
		t.Fatalf("expected deny-net profile to re-allow loopback bind:\n%s", prof)
	}
}

func TestBuildProfileUsesAutoDiscoveredIgnoreFilesFromReadme(t *testing.T) {
	root := t.TempDir()

	cursorIgnore := filepath.Join(root, ".cursorignore")
	if err := os.WriteFile(cursorIgnore, []byte(".env\n*.pem\n"), 0644); err != nil {
		t.Fatalf("write .cursorignore: %v", err)
	}

	prof, loadedFiles, err := buildProfile(root, true, nil, nil, false, false)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	if len(loadedFiles) != 1 || loadedFiles[0] != cursorIgnore {
		t.Fatalf("loadedFiles = %v, want [%q]", loadedFiles, cursorIgnore)
	}
	if !strings.Contains(prof, `\.env`) {
		t.Fatalf("expected profile to include .env deny from auto-discovered file:\n%s", prof)
	}
	if !strings.Contains(prof, `\.pem`) {
		t.Fatalf("expected profile to include *.pem deny from auto-discovered file:\n%s", prof)
	}
}

func TestBuildProfileRespectsReadmeSourcePrecedence(t *testing.T) {
	root := t.TempDir()

	cursorIgnore := filepath.Join(root, ".cursorignore")
	if err := os.WriteFile(cursorIgnore, []byte(".env\n"), 0644); err != nil {
		t.Fatalf("write .cursorignore: %v", err)
	}

	extraIgnore := filepath.Join(root, "extra.ignore")
	if err := os.WriteFile(extraIgnore, []byte("!.env\n"), 0644); err != nil {
		t.Fatalf("write extra ignore: %v", err)
	}

	prof, loadedFiles, err := buildProfile(root, true, []string{extraIgnore}, []string{".env"}, false, false)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	wantLoadedFiles := []string{cursorIgnore, extraIgnore}
	if len(loadedFiles) != len(wantLoadedFiles) {
		t.Fatalf("expected %d loaded files, got %d", len(wantLoadedFiles), len(loadedFiles))
	}
	for i, want := range wantLoadedFiles {
		if loadedFiles[i] != want {
			t.Fatalf("loadedFiles[%d] = %q, want %q", i, loadedFiles[i], want)
		}
	}

	firstDeny := strings.Index(prof, "(deny file*")
	allow := strings.Index(prof, "(allow file*")
	lastDeny := strings.LastIndex(prof, "(deny file*")
	if firstDeny == -1 || allow == -1 || lastDeny == -1 {
		t.Fatalf("expected profile to contain deny/allow/deny ordering:\n%s", prof)
	}
	if !(firstDeny < allow && allow < lastDeny) {
		t.Fatalf("expected auto-ignore deny, then extra-file allow, then CLI deny:\n%s", prof)
	}
}

func TestCollectPatternInputsCanDisableAutoIgnore(t *testing.T) {
	root := t.TempDir()

	autoIgnore := filepath.Join(root, ".cursorignore")
	if err := os.WriteFile(autoIgnore, []byte("auto-deny\n"), 0644); err != nil {
		t.Fatalf("write .cursorignore: %v", err)
	}

	inputs, err := collectPatternInputs(root, false, nil, nil)
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.Patterns) != 0 {
		t.Fatalf("expected auto ignore discovery to be disabled, got %d patterns", len(inputs.Patterns))
	}
	if len(inputs.LoadedFiles) != 0 {
		t.Fatalf("expected no loaded files, got %v", inputs.LoadedFiles)
	}
}

func TestCollectPatternInputsDeduplicatesPatternFiles(t *testing.T) {
	root := t.TempDir()

	autoIgnore := filepath.Join(root, ".aiignore")
	if err := os.WriteFile(autoIgnore, []byte("auto-deny\n"), 0644); err != nil {
		t.Fatalf("write .aiignore: %v", err)
	}

	inputs, err := collectPatternInputs(root, true, []string{autoIgnore, filepath.Join(root, ".", ".aiignore")}, nil)
	if err != nil {
		t.Fatalf("collectPatternInputs: %v", err)
	}

	if len(inputs.Patterns) != 1 {
		t.Fatalf("expected duplicate pattern files to load once, got %d patterns", len(inputs.Patterns))
	}
	if len(inputs.LoadedFiles) != 1 {
		t.Fatalf("expected duplicate pattern files to load once, got %d loaded files", len(inputs.LoadedFiles))
	}
	if inputs.Patterns[0].Value != "auto-deny" {
		t.Fatalf("pattern value = %q, want %q", inputs.Patterns[0].Value, "auto-deny")
	}
	if inputs.LoadedFiles[0] != autoIgnore {
		t.Fatalf("loadedFiles[0] = %q, want %q", inputs.LoadedFiles[0], autoIgnore)
	}
}

func TestWriteLoadedFilesIncludesEachPath(t *testing.T) {
	var buf bytes.Buffer

	writeLoadedFiles(&buf, []string{"/tmp/.cursorignore", "/tmp/.aiignore"})

	out := buf.String()
	if !strings.Contains(out, "sbox: loaded ignore files:\n") {
		t.Fatalf("expected loaded files header in output:\n%s", out)
	}
	if !strings.Contains(out, "  /tmp/.cursorignore\n") {
		t.Fatalf("expected first loaded file in output:\n%s", out)
	}
	if !strings.Contains(out, "  /tmp/.aiignore\n") {
		t.Fatalf("expected second loaded file in output:\n%s", out)
	}
}

func TestWriteLoadedFilesEmptyIsNoop(t *testing.T) {
	var buf bytes.Buffer
	writeLoadedFiles(&buf, nil)
	if buf.Len() != 0 {
		t.Fatalf("expected no output for empty loaded files, got:\n%s", buf.String())
	}
}
