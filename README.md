# sbox

A macOS sandbox tool for AI coding agents and untrusted code execution. Implemented as a wrapper around `sandbox-exec`. Protects sensitive files from being read or modified by wrapping any command with kernel-enforced deny rules.

> [!WARNING]
> This project is mostly vibe-coded

## Usage

```bash
echo "API_KEY=secret" > .env

# Pass deny patterns with `-d/--deny`
sbox -d ".env*" cat .env
cat: .env: Operation not permitted

# Or load additional ignore file(s)
# Ignore files used by popular AI tools (.aiignore, .cursorignore, etc.) are auto-discovered in the project root
sbox -f .gitignore claude

# Prevent writes outside the project directory and the current temp directory
sbox --deny-write codex

# Block non-loopback network access
sbox --deny-net python untrusted.py

# Jump to a sandboxed shell
sbox $SHELL

# Show compiled SBPL profile
sbox --root / -d '.env' -d '*.pem' -d '~/.ssh/' --deny-net --dry-run
(version 1)
(allow default)
(deny file* (regex "^/(|.*/)\\.env(|/.*)$"))
(deny file* (regex "^/(|.*/)([^/]*)\\.pem(|/.*)$"))
(deny file* (subpath "/Users/test/.ssh"))
(deny network*)
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
```

## Why use it?

Ignore files usually prevent indexing or context loading. They do not stop an agent with shell access from running `cat .env` or traversing a secrets directory.

`sbox` helps close that gap by enforcing the same restrictions at execution time:

- Reuse existing ignore files like `.aiignore` and `.cursorignore`
- Apply the same restrictions to any wrapped command
- Keep those restrictions in child processes
- Add optional `--deny-write` and `--deny-net` protections

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

This project is macOS-only.

```bash
ARCHIVE="sbox_Darwin_$(uname -m).tar.gz"
curl -fL "https://github.com/qweeze/sbox/releases/latest/download/${ARCHIVE}" -o "/tmp/${ARCHIVE}"
sudo tar -xzf "/tmp/${ARCHIVE}" -C /usr/local/bin sbox
```

### Pattern Syntax

Ignore files and CLI `-d/--deny` values use gitignore syntax. Malformed patterns are rejected.

### Absolute CLI Paths

Values passed via `-d` that begin with `/` or `~/` are treated as absolute filesystem paths and are independent of `--root`.

- Without glob metacharacters (`*`, `?`, `[`), they become literal SBPL `subpath` rules.
- With globs, they are compiled against the filesystem root, so a value like `/Users/me/secrets/*` matches the real filesystem location regardless of the project root.
- `~/` is expanded to the user's home directory.

### Auto-discovered Ignore Files

When `--no-auto-ignore` is not set, `sbox` checks the project root for these files and loads every one that exists:

- `.aiderignore`
- `.aiexclude`
- `.aiignore`
- `.augmentignore`
- `.clineignore`
- `.codeiumignore`
- `.continueignore`
- `.cursorignore`
- `.geminiignore`
- `.rooignore`

### Pattern Loading Order

Patterns are loaded from multiple sources. Last match wins.

1. Auto-discovered ignore files in the order above
2. `-f` files
3. `-d` CLI patterns

This means CLI rules override rules loaded from files.

## Limitations

- macOS only. The current implementation depends on `sandbox-exec`.
- `sandbox-exec` is deprecated by Apple, but still functional on current macOS releases.
- Environment variables are not filtered, so secrets passed via env vars are still visible.
- Rules operate on resolved real paths, so symlinks into protected directories are blocked too.

## License

MIT
