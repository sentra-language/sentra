# Contributing to Sentra

Thanks for your interest in contributing! Sentra is a security-focused
programming language, and we aim to keep both the codebase and the supply
chain trustworthy.

## Getting started

```bash
git clone https://github.com/sentra-language/sentra.git
cd sentra
go build ./cmd/sentra
./sentra run examples/basics/hello.sn
```

Requirements: Go (version pinned in [go.mod](go.mod)). No CGO is needed.

## Development workflow

1. Fork the repo and create a branch from `main`.
2. Make your change. Match the style of the surrounding code; run `gofmt`
   on files you touch.
3. Verify locally:
   ```bash
   go build ./...
   go test ./...
   ```
4. Open a pull request. CI runs build, tests, and an example smoke test on
   Linux, macOS, and Windows — it must pass.

## Project layout

- `cmd/sentra/` — CLI entry point and commands
- `internal/lexer`, `internal/parser` — front end
- `internal/compiler`, `internal/vm` — stack-based compiler/VM (legacy, `--oldvm`)
- `internal/compregister`, `internal/vmregister`, `internal/jit` — register-based VM with JIT (default)
- `internal/network`, `internal/security`, `internal/siem`, … — stdlib modules
- `examples/` — runnable examples (also used as smoke tests)
- `tests/` — integration and performance tests

## Commit and attribution policy

- Write clear commit messages describing **what** and **why**.
- Commits are authored by their human contributor. Do not add AI tools as
  co-authors or include tool-generated attribution lines
  (e.g. `Co-Authored-By` trailers for AI assistants or "Generated with ..."
  footers) in commit messages or code.
- Do not commit binaries, build output, editor configs, or `CLAUDE.md`-style
  assistant files (these are gitignored).

## Reporting security issues

Do **not** open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## Releases

Releases are tagged (`vX.Y.Z`) and built exclusively by the
[release workflow](.github/workflows/release.yml): cross-platform binaries,
SHA-256 checksums, keyless cosign signatures, and SBOMs. Maintainers never
upload locally built binaries.
