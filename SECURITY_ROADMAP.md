# Security Roadmap

Sentra's claim is "security-focused". This document is the concrete plan for
making that true *by construction* — in the language and runtime, not just in
the standard library's feature list. Items are ordered roughly by impact.

## Done

- ✅ Reproducible, auditable releases: built in public CI, SHA-256
  checksums, keyless cosign signatures, SBOMs ([SECURITY.md](SECURITY.md))
- ✅ CI on every push/PR: build, tests, cross-platform smoke tests
- ✅ Dependency vulnerability scanning (`govulncheck`) in CI
- ✅ Static security analysis (`gosec`) in CI (advisory while findings are
  triaged)
- ✅ Memory-safe implementation language (Go, `CGO_ENABLED=0`)
- ✅ Private vulnerability reporting via GitHub Security Advisories

## Next: runtime security (the "secure by nature" work)

### 1. Capability-based permissions (highest priority)
Scripts should not get ambient authority. A script's manifest
(`sentra.json`) declares the capabilities it needs — `net`, `fs:read`,
`fs:write`, `exec`, `env` — and the VM enforces them at the built-in
function boundary. Deny by default:

```bash
sentra run scanner.sn                # fails: script wants net, not granted
sentra run scanner.sn --allow net    # explicit grant
```

This is enforceable cheaply because all I/O flows through registered
built-ins in the VM — there is a single choke point.

### 2. Sandbox mode
`sentra run --sandbox`: no filesystem, network, process, or environment
access at all. For running untrusted or third-party scripts (e.g. analyzing
a suspicious automation script without letting it phone home).

### 3. Resource limits
VM-level instruction budgets, memory caps, and wall-clock timeouts
(`--max-mem`, `--timeout`) so a hostile or buggy script cannot exhaust the
host. Security tooling routinely processes attacker-controlled input; the
runtime must assume it.

### 4. Fuzzing the front end
Go native fuzz targets for the lexer, parser, and bytecode deserializer
(`.snb` loading is attacker-reachable input), run continuously in CI. The
parser currently panics on some malformed input — panics on untrusted input
become denial-of-service bugs.

### 5. Module/package integrity
Before the package registry launches: lockfiles with content hashes
(`sentra.sum`, like `go.sum`), signature verification for registry packages,
and no install-time code execution. Remote imports (`sentra get <git-url>`)
should record and verify commit hashes.

### 6. Audit `unsafe` usage
`internal/vmregister/value.go` uses `unsafe.Pointer` (flagged by `go vet`)
for value representation. Audit and document the invariants, or replace with
safe representations where the performance cost is acceptable.

### 7. Secure-by-default stdlib behavior
- TLS verification on by default in HTTP/network built-ins (opt *out*, never
  silently off)
- Constant-time comparison helpers for secrets in the crypto module
- Path traversal protection in file built-ins when running with `fs`
  capability scoping

## Research / later

- Taint tracking: mark values from network/file input and warn (or fail)
  when they flow into `exec`-like sinks without sanitization
- SLSA build provenance attestations on releases
- Deterministic/replayable execution mode for forensic analysis

Contributions to any of these are welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Design discussions happen in GitHub
issues tagged `security-design`.
