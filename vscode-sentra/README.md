# Sentra Language Support for VSCode

Official VSCode extension for the Sentra Security Automation Language.

## Features

### Syntax Highlighting
- Full syntax highlighting for `.sn` and `.sentra` files
- Security function highlighting with semantic colors
- Comment and string support

### IntelliSense
- Auto-completion for all built-in security functions
- Function signature help
- Hover documentation for functions
- Smart bracket matching

### Code Execution
- Run current file (`Ctrl+F5`)
- Run selected code
- Integrated output panel
- Automatic interpreter detection

### Code Snippets
- Port scanning templates
- Web vulnerability scanning
- File integrity monitoring
- Worker pool creation
- Security report generation
- Database security checks

### Linting & Diagnostics
- Real-time syntax checking
- Undefined variable detection
- Security best practice warnings

### Package Management
- Install packages from GitHub (like Go)
- Package discovery
- Dependency management

## Installation

1. Install the extension from VSCode Marketplace (search "Sentra")
2. Or install manually:
   ```bash
   cd vscode-sentra
   npm install
   npm run compile
   code --install-extension sentra-lang-0.1.0.vsix
   ```

## Configuration

Configure the extension in VSCode settings:

```json
{
  "sentra.interpreterPath": "sentra",
  "sentra.autoDetectInterpreter": true,
  "sentra.linting.enabled": true,
  "sentra.linting.lintOnSave": true,
  "sentra.packageManager.registry": "https://github.com/sentra-packages"
}
```

## Usage

### Running Scripts
- Open a `.sn` file
- Press `F5` or click the play button to run
- View output in the Sentra output panel

### Installing Packages
- Command Palette: `Sentra: Install Package`
- Enter package path: `github.com/user/package`
- Package will be installed to `sentra_modules/`

### REPL
- Command Palette: `Sentra: Open REPL`
- Interactive Sentra console opens in terminal

## Package Manager Design

The Sentra package system follows Go's approach:

### Package Structure
```
project/
├── main.sn
├── sentra.mod          # Module definition
└── sentra_modules/     # Dependencies
    └── github.com/
        └── user/
            └── package/
```

### sentra.mod Format
```
module github.com/myuser/myproject

require (
    github.com/sentra-security/core v1.0.0
    github.com/sentra-security/network v2.1.0
)
```

### Import Syntax
```sentra
import "github.com/sentra-security/network"
import scanner "github.com/user/custom-scanner"
```

## Build System

The build system compiles Sentra scripts to:
1. **Bytecode** - For the VM
2. **Native** - Using Go compiler (future)
3. **WebAssembly** - For browser execution (future)

### Build Commands
```bash
# Compile to bytecode
sentra build main.sn -o app.snc

# Run compiled bytecode
sentra run app.snc

# Build with dependencies
sentra build --with-deps

# Cross-compile
sentra build --target=wasm
```

## Contributing

Contributions welcome! The extension is open source.

## License

MIT License