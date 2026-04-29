# sbox — OS-level sandbox for AI coding agents

## Problem

AI coding agents (Claude Code, Codex, OpenCode, Cursor, etc.) can read any file accessible to the user. Sensitive files like `.env`, credentials, private keys, and config files with secrets are all fair game. Existing mitigations:

- **Context exclusion** (`.cursorignore`, `.continueignore`, `.augmentignore`) only prevents files from being *indexed* — an agent with shell access can still `cat .env`.
- **Built-in sandboxing** (Claude Code, Codex CLI) is tool-specific and not user-configurable via a simple file.
- **Docker containers** are heavyweight and can't easily wrap arbitrary local CLI tools.

**sbox** provides OS-level file access enforcement, configured via familiar ignore files already used by AI tools, as a tool-agnostic wrapper.

## Solution

```bash
# Given a supported ignore file at project root:
#   .env
#   .env.*
#   secrets/
#   *.pem

sbox claude    # Claude Code can't read .env, secrets/, *.pem
sbox codex     # Same protection for Codex
sbox opencode  # Same for any tool
```

Under the hood, `sbox` translates supported ignore-file patterns into an `sandbox-exec` (macOS) profile that denies file access at the OS/kernel level. The sandbox is inherited by all child processes — there is no escape via subprocess spawning.

## Architecture

```
ignore files ──parse──> patterns ──compile──> SBPL profile ──> sandbox-exec <command>
                                                                │
                                                    ┌───────────┘
                                                    ▼
                                              command runs
                                              with denied
                                              file access
```

### Components

1. **CLI entry point** — parse args, collect patterns, exec into sandbox
2. **Pattern compiler** — convert auto-discovered ignore files and CLI patterns into project-scoped regexes
3. **Profile compiler** — convert compiled patterns to SBPL deny rules
4. **Executor** — currently call `sandbox-exec -p <profile> <command> [args...]`

## Ignore file format

Same syntax as `.gitignore`:

```gitignore
# Secrets
.env
.env.*
*.pem
*.key

# Directories
secrets/
.aws/

# Negation — re-allow specific files
!.env.example

# Anchored patterns (relative to project root)
/config/production.yml

# Double-star
**/credentials.json
```

Malformed patterns are rejected with an explicit error instead of being silently ignored.

### Auto-discovered ignore files

Unless `--no-auto-ignore` is set, `sbox` checks the effective project root for these files and loads every one that exists, in this order:

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

### Supported patterns (MVP)

| Pattern | Meaning | SBPL translation |
|---------|---------|-----------------|
| `.env` | File named `.env` anywhere | `(regex "/\\.env$")` |
| `.env.*` | Files like `.env.local` anywhere | `(regex "/\\.env\\.[^/]*$")` |
| `secrets/` | Directory `secrets` anywhere | exact directory rule using `vnode-type DIRECTORY`, plus a descendant regex |
| `*.pem` | Files ending in `.pem` | `(regex "/[^/]*\\.pem$")` |
| `key?.pem` | `key` + one char + `.pem` | `(regex "/key[^/]\\.pem$")` |
| `[a-c].txt` | Single-character class / range | `(regex "/[a-c]\\.txt$")` |
| `[!a-c].txt` | Negated character class | `(regex "/[^a-c/]\\.txt$")` |
| `config/prod.yml` or `/config/prod.yml` | Root-relative in the project | `(literal "<root>/config/prod.yml")` |
| `**/creds.json` | `creds.json` at any depth | `(regex "/creds\\.json$")` |
| `!.env.example` | Re-allow after previous deny | `(allow file* ...)` rule |
| `dir/**` | Everything inside `dir` | `(subpath "<root>/dir")` |

### Deferred (post-MVP)

- Multiple supported ignore files in subdirectories (nested scope)

## SBPL profile generation

### Strategy: allow-default with deny rules

```scheme
(version 1)
(allow default)

;; --- deny rules from ignore files ---
(deny file*   (regex "<pattern>"))
;; ... one deny per pattern ...

;; --- negation (!pattern) becomes allow rules ---
(allow file*  (regex "<pattern>"))

;; --- default-on: close the LaunchServices/AppleEvents spawn escape ---
(deny mach-lookup (global-name-prefix "com.apple.coreservices."))
(deny mach-lookup (global-name-prefix "com.apple.lsd."))
(deny mach-lookup (global-name "com.apple.appleeventsd"))
(deny appleevent-send)

;; --- (optional) --deny-write: deny writes outside project root ---
(deny file-write*  (require-all
    (require-not (subpath "<project-root>"))
    (require-not (subpath "<tmpdir>"))
))
```

SBPL uses **last-match-wins** evaluation (verified experimentally), which matches `.gitignore` semantics. Rules are emitted in order: auto-discovered ignore files in fixed filename order, then `-f` file patterns, then CLI `--deny` patterns. This means CLI rules override file-loaded ones.

### Deny scope

Each denied pattern generates a single `file*` rule that covers all file operations — reads, writes, metadata, creation, and deletion. This means `ls` in a denied directory won't show the files, and `cat`/`cp`/`mv`/`rm` all fail.

### Path resolution

Patterns must be converted to absolute paths because SBPL operates on resolved (real) paths:

1. **Project root**: Use CWD, or the path passed via `-r`.
2. **Symlink resolution**: Resolve the project root via `realpath()`. On macOS, `/tmp` → `/private/tmp`, etc.
3. **Root-relative patterns** (patterns with a leading slash, or a slash in the middle like `config/prod.yml`): Prefix with the resolved project root. A leading `**/` remains unanchored.
4. **Unanchored patterns** (simple names like `*.env`): Generate regex that matches anywhere in the path.

### Regex escaping

Characters `.`, `+`, `(`, `)`, `{`, `}`, `|`, `^`, `$`, `[`, `]` in the pattern must be escaped when converting to POSIX regex. The glob `*` becomes `[^/]*`, `**` becomes `.*`.

## CLI interface

```
sbox [options] <command> [args...]
```

### Options

```
  -d, --deny <pattern>    Add a deny pattern (can be repeated)
  -f, --file <path>       Additional ignore file (can be repeated)
  -r, --root <path>       Project root (default: current directory)
  -v, --verbose           Print loaded ignore files and generated sandbox profile details to stderr
  -n, --dry-run           Print profile without executing
      --no-auto-ignore    Disable automatic loading of supported ignore files from the project root
      --deny-net          Deny network access (localhost still allowed)
      --deny-write        Deny all writes outside project root and $TMPDIR
      --allow-spawn       Re-enable LaunchServices/AppleEvents (default off; see "spawn escape" below)
```

### CLI pattern semantics

- CLI values passed via `-d` that begin with `/` or `~/` are treated as absolute filesystem paths (e.g. `~/.ssh`)
- Other CLI values use the same ignore-file syntax as file-loaded rules

### Ignore file resolution

Patterns are loaded from multiple sources, in order (last-match-wins):

1. **Auto-discovered**: Supported ignore files in project root, loaded in the fixed order above
2. **CLI `--file`**: Additional ignore files specified via `-f` flags
3. **CLI `--deny`**: Inline patterns specified via `-d` flags

### Examples

```bash
# Basic usage — reads supported ignore files from project root
sbox claude

# Add extra patterns via CLI
sbox -d '.env' -d '*.pem' claude

# Use an additional ignore file
sbox -f ~/.secretsignore claude

# Deny an absolute path directly from the CLI
sbox -d ~/.ssh codex

# Combine: auto-discovered ignore files + extra patterns + write protection
sbox --deny-write -d 'secrets/' claude

# See what profile would be generated
sbox --dry-run claude

# Wrap any command
sbox bash                  # sandboxed shell session
sbox python agent.py       # sandboxed Python script
sbox npx opencode          # sandboxed OpenCode
```

## Implementation language

**Go** — for the following reasons:

- Single static binary, no runtime dependencies
- Easy cross-compilation for future Linux support
- Good stdlib for path manipulation, regex, file parsing
- Fast startup (important since this wraps interactive tools)
- `syscall.Exec` for clean exec-into-sandbox (replaces process, no extra PID)

### Project structure

```
sbox/
  cmd/sbox/main.go        # CLI entry point, arg parsing
  internal/
    profile/sbpl.go        # Pattern compiler + SBPL profile generator
    profile/sbpl_test.go
  go.mod
  go.sum
```

### Dependencies

- Runtime path depends on the Go stdlib plus `github.com/spf13/pflag` for CLI parsing.
- Tests use `github.com/sabhiram/go-gitignore` to cross-check pattern semantics.
- Arg parsing uses `github.com/spf13/pflag`.

## Key design decisions

### Q: Why not an allow-list (deny-default) approach?
An allow-list profile would need to enumerate every system path the wrapped tool needs (dylibs, frameworks, Mach services, temp dirs, etc.). This is fragile and varies by tool. The deny-list approach (`allow default` + specific denies) is robust: everything works as normal except the explicitly blocked paths.

### Q: Why deny `file*` and not just `file-read-data`?
Denying only `file-read-data` would still let the agent see that the file *exists* (via `stat`, `ls`, `find`). Denying `file*` makes the file fully invisible and unmodifiable — the agent doesn't even know it's there. This is more secure since an agent seeing `.env` exists might try to work around the restriction.

### Q: How does this interact with tools that have their own sandboxing?
If Claude Code or Codex already applies `sandbox-exec`, the inner sandbox will also be active. macOS allows this — the effective policy is the intersection (most restrictive combination). So `sbox` can only make things *more* restrictive, never less. This is safe.

### Q: What about file-write-data?
An agent that can't read `.env` but can write to it could overwrite it with garbage. Denying both reads and writes is the safe default for ignore-file patterns.

### Q: What does `--deny-write` do exactly?
It denies `file-write*` (writes only, not reads) for everything **outside** the project root and the current temp directory (`os.TempDir()`, usually derived from `$TMPDIR`). This prevents an agent from modifying files in your home directory, other projects, system paths, etc. Writes to ignore-file-denied paths within the project are still blocked regardless. This is opt-in because some tools legitimately write to `~/.config`, caches, etc.

### Q: Why deny LaunchServices and AppleEvents by default?
`open /path/to/Pwn.app` does not spawn the app as a child of the wrapped process — it sends a Mach message to `launchservicesd`, which asks `launchd` to fork the app. The new process inherits launchd's context, so the sandbox does not apply to it. The same trick works through AppleEvents (`osascript -e 'tell app "Finder" to ...'`). Empirically, denying just `com.apple.coreservices.launchservicesd` is not enough — `open` falls through to other `com.apple.coreservices.*` services (e.g. `quarantine-resolver`). So the default profile denies the whole `com.apple.coreservices.` and `com.apple.lsd.` Mach prefixes plus `appleeventsd` and `appleevent-send`. CLI agents do not normally need any of these, so the cost is low; users who explicitly need them can pass `--allow-spawn`, which leaves the escape open.

### Q: What about processes that resolve paths differently?
Some tools may use relative paths internally. `sandbox-exec` resolves all paths to absolute real paths before matching, so as long as our regex patterns account for the resolved root, this works regardless of how the tool references files.

## Threat model

**What sbox protects against:**
- Agent reading sensitive files (.env, keys, credentials)
- Agent exfiltrating secret content via shell commands (`cat`, `grep`, etc.)
- Agent modifying/deleting protected files
- Child processes inheriting permissions (no escape via subprocess)
- LaunchServices/AppleEvents spawn-via-launchd escape (`open <app>`, `osascript -e 'tell app …'`) — denied by default; use `--allow-spawn` to opt out

**What sbox does NOT protect against (out of scope for MVP):**
- Network exfiltration (agent reads a file it CAN access and sends it over the network) — mitigated by `--deny-net` flag
- Agent modifying its own sandbox profile or ignore files — mitigated because sandbox is set before the process starts; modifying the file has no effect on the running sandbox
- Environment variables (e.g., secrets in `$DATABASE_URL`) — separate concern, could be addressed with `(deny process-info-pidinfo)` in future
- Clipboard, IPC, or other side channels

## Testing strategy

1. **Unit tests**: Pattern parsing, regex generation, profile compilation
2. **Integration tests**: Actually run `sandbox-exec` with generated profiles and verify file access is denied
3. **Pattern compatibility tests**: Cross-check ignore-file regex compilation against `github.com/sabhiram/go-gitignore` for supported patterns

## Future work

- **Linux support**: Add firejail or bubblewrap backend (deny paths via `--blacklist` or mount namespace isolation). This will require introducing a backend abstraction; the current implementation is SBPL-specific.
- **Environment variable filtering**: Strip sensitive env vars before exec
- **Nested ignore files**: Support supported ignore files in subdirectories (scoped rules)
- **Presets**: Curated ignore files for common sensitive paths (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gh`) — users can reference them via `-f`
- **Shell integration**: `sbox shell` to drop into a sandboxed shell with prompt indicator
- **`--allow-write <path>`**: Whitelist additional writable paths when using `--deny-write`
