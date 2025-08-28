# Sentra Command Reference

## Project Management Commands

### `sentra init [project-name] [template]`
Creates a new Sentra project from predefined templates.

**Templates:**
- `security-scanner` - Network security scanner application
- `web-api` - RESTful API server
- `cli-tool` - Command-line application
- `library` - Reusable Sentra library

**Example:**
```bash
sentra init myapp web-api
cd myapp
sentra run main.sn
```

### `sentra build`
Compiles a Sentra project into an executable wrapper.

- Reads configuration from `sentra.toml`
- Default input: `main.sn`
- Default output: `output` (or `output.exe` on Windows)
- Creates a platform-specific executable wrapper

**Example:**
```bash
sentra build
./output  # Run the built executable
```

### `sentra clean`
Removes build artifacts.

```bash
sentra clean
```

## Module Management Commands

### `sentra mod init <module-path>`
Initializes module management for dependency tracking.

**Example:**
```bash
sentra mod init github.com/myuser/myproject
```

### `sentra get <package>`
Installs a package dependency.

```bash
sentra get github.com/sentra-security/network@latest
```

### `sentra mod tidy`
Cleans up unused dependencies.

```bash
sentra mod tidy
```

### `sentra mod list`
Lists all project dependencies.

```bash
sentra mod list
```

## Development Commands

### `sentra run <file.sn>`
Runs a Sentra script directly.

```bash
sentra run main.sn
sentra run examples/hello.sn
```

### `sentra repl`
Starts an interactive REPL session.

```bash
sentra repl
> let x = 10
> log(x * 2)
20
```

### `sentra debug <file.sn>`
Runs a script with the interactive debugger.

```bash
sentra debug main.sn
```

### `sentra test [files...]`
Runs test files (files ending with `_test.sn`).

```bash
sentra test                    # Run all tests
sentra test unit_test.sn      # Run specific test
```

## Code Quality Commands

### `sentra check <file.sn>`
Validates syntax without executing the code.

```bash
sentra check main.sn
```

### `sentra lint <file.sn>`
Checks for code quality issues (unused variables, etc.).

```bash
sentra lint main.sn
```

### `sentra fmt <file.sn>`
Formats Sentra code according to standard style.

```bash
sentra fmt main.sn
```

### `sentra doc [files...] [-o output-dir]`
Generates documentation from Sentra source files.

```bash
sentra doc                     # Document all files
sentra doc main.sn -o docs    # Document specific file
```

## Project Structure

### sentra.toml
Project configuration file:

```toml
[project]
name = "my-app"
version = "1.0.0"
description = "My Sentra application"

[dependencies]
network = "1.0.0"
crypto = "1.0.0"

[build]
main = "main.sn"
output = "myapp"
```

### sentra.mod
Module definition file (created by `sentra mod init`):

```
module github.com/user/project

require (
    github.com/sentra-security/network v1.0.0
    github.com/sentra-security/crypto v1.0.0
)
```

## Build Output

When you run `sentra build`, it creates:

1. **On Linux/Mac:** Shell script wrapper
   - Executable file (e.g., `./myapp`)
   - Checks for Sentra runtime
   - Runs the original source with arguments

2. **On Windows:** Batch file wrapper
   - Executable file (e.g., `myapp.exe`)
   - Checks for Sentra runtime
   - Runs the original source with arguments

## Future Enhancements

- **True compilation:** Compile to standalone bytecode executable
- **Cross-compilation:** Build for different platforms
- **Optimization levels:** Debug vs Release builds
- **Static linking:** Bundle runtime with executable
- **Package registry:** Central repository for Sentra packages