# sbox

OS-level sandbox for AI coding agents. Protects sensitive files from being read or modified by wrapping any command with kernel-enforced deny rules.

Unlike tool-specific ignore files, `sbox` enforces restrictions at the OS level. If a file is denied, the wrapped command and its child processes cannot read it, list it, or modify it.

Disclaimer: this project is vibe-coded. Treat it as experimental security tooling, review the generated profile when needed, and verify behavior in your own environment before relying on it.

## Quick Start

The simplest example:

```bash
echo "API_KEY=secret" > .env
echo ".env" > .aiignore

sbox cat .env
cat: .env: Operation not permitted
```

The same rule still applies inside a sandboxed shell:

```bash
sbox $SHELL
cat .env
cat: .env: Operation not permitted
exit
```

A more realistic setup for agent sessions:

```bash
cat > .cursorignore <<'EOF'
.env
.env.*
*.pem
secrets/
EOF

sbox codex
sbox claude
sbox opencode
```

## Why use it?

Ignore files usually prevent indexing or context loading. They do not stop an agent with shell access from running `cat .env` or traversing a secrets directory.

`sbox` closes that gap:

- Reuse existing ignore files like `.aiignore` and `.cursorignore`
- Apply the same restrictions to any wrapped command
- Keep those restrictions in child processes
- Add optional `--deny-write` and `--deny-net` protections

## Usage

```bash
sbox [options] <command> [args...]
```

### Examples

```bash
# Use auto-discovered ignore files from the project root
sbox codex

# Sandbox any command, not just agents
sbox bash
sbox python agent.py
sbox cat .env

# Add patterns directly from the CLI
sbox -d '.env' -d '*.pem' -d 'secrets/' claude

# Use an extra ignore file alongside auto-discovered ones
sbox -f ~/.config/sbox/ignore claude

# Deny an absolute path directly from the CLI
sbox -d ~/.ssh codex

# Prevent writes outside the project directory
sbox --deny-write claude

# Block non-loopback network access
sbox --deny-net codex

# Combine protections
sbox --deny-write -d '.env' -d '*.key' bash

# Inspect the generated profile
sbox --dry-run codex

# See which ignore files were loaded
sbox -v codex
```

### Options

| Flag | Description |
|------|-------------|
| `-d`, `--deny <pattern>` | Add a deny pattern (can be repeated) |
| `-f`, `--file <path>` | Additional ignore file (can be repeated) |
| `-r`, `--root <path>` | Project root (default: current directory) |
| `-v`, `--verbose` | Print loaded ignore files and generated sandbox profile details to stderr |
| `-n`, `--dry-run` | Print profile without executing |
| `--no-auto-ignore` | Disable automatic loading of supported ignore files from the project root |
| `--deny-write` | Deny all writes outside project root and `$TMPDIR` |
| `--deny-net` | Deny non-loopback network access (localhost still allowed) |

## Installation

Requires macOS and Go 1.24+.

Install the latest GitHub release binary:

```bash
curl -fsSL https://raw.githubusercontent.com/qweeze/sbox/main/scripts/install.sh | sh
```

Install to a custom directory:

```bash
curl -fsSL https://raw.githubusercontent.com/qweeze/sbox/main/scripts/install.sh | INSTALL_DIR="$HOME/.local/bin" sh
```

If you already have Go, install the latest version with:

```bash
go install github.com/qweeze/sbox/cmd/sbox@latest
```

Or build from a checkout:

```bash
go build -o ./bin/sbox ./cmd/sbox
```

GitHub release archives are built automatically for macOS on `v*` tags.

## Ignore File Format

Auto-discovered ignore files and files passed with `-f` use `.gitignore`-style syntax:

```gitignore
# Secrets
.env
.env.*
*.pem
*.key

# Directories
secrets/
.aws/

# Negation — re-allow after a previous deny
!.env.example

# Anchored to project root
/config/production.yml

# Double-star (match at any depth)
**/credentials.json
```

Malformed patterns are rejected with an explicit error instead of being silently ignored. Use escaped brackets `\[` and `\]` for literal bracket characters.

### CLI absolute paths

Values passed via `-d` that begin with `/` or `~/` are treated as absolute filesystem paths and are independent of `--root`.

- Without glob metacharacters (`*`, `?`, `[`), they become literal SBPL `subpath` rules.
- With globs, they are compiled against the filesystem root, so a value like `/Users/me/secrets/*` matches the real filesystem location regardless of the project root.
- `~/` is expanded to the user's home directory.

## Auto-discovered Ignore Files

When `--no-auto-ignore` is not set, `sbox` checks the project root for these files and loads every one that exists, in this order:

1. `.aiderignore`
2. `.aiexclude`
3. `.aiignore`
4. `.augmentignore`
5. `.clineignore`
6. `.codeiumignore`
7. `.continueignore`
8. `.cursorignore`
9. `.geminiignore`
10. `.rooignore`

## Pattern Loading Order

Patterns are loaded from multiple sources. Last match wins.

1. Auto-discovered ignore files in the order above
2. `-f` files
3. `-d` CLI patterns

This means CLI rules override rules loaded from files.

## How It Works

```text
ignore files -> parsed patterns -> SBPL profile -> sandbox-exec <command>
```

The generated profile uses an allow-by-default strategy plus specific deny rules, which keeps normal tooling working while blocking the paths you marked as sensitive.

## Development

### Build

```bash
go build -o ./bin/sbox ./cmd/sbox
```

### Test

```bash
go test ./...
go test ./... -v
go test ./cmd/sbox
go test ./internal/profile/...
go test -v -run TestSandbox
```

## Limitations

- macOS only. The current implementation depends on `sandbox-exec`.
- `sandbox-exec` is deprecated by Apple, but still functional on current macOS releases.
- Environment variables are not filtered, so secrets passed via env vars are still visible.
- Rules operate on resolved real paths, so symlinks into protected directories are blocked too.

## License

MIT
