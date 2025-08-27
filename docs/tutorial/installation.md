---
layout: default
title: Installation
parent: Tutorial
nav_order: 1
---

# Installing Sentra

Sentra can be installed in several ways depending on your operating system and preferences.

## Quick Installation

### Option 1: Binary Releases (Recommended)
Download the latest pre-compiled binary for your platform:

1. Visit the [releases page](https://github.com/sentra-language/sentra/releases)
2. Download the appropriate binary for your system:
   - **Windows**: `sentra-windows-amd64.exe`
   - **macOS**: `sentra-macos-amd64` (Intel) or `sentra-macos-arm64` (Apple Silicon)
   - **Linux**: `sentra-linux-amd64` or `sentra-linux-arm64`
3. Make it executable and add to PATH

### Option 2: Build from Source

Prerequisites:
- Go 1.21 or later
- Git

```bash
# Clone the repository
git clone https://github.com/sentra-language/sentra.git
cd sentra

# Build Sentra
make sentra
# or
go build -o sentra ./cmd/sentra

# Add to PATH (optional)
sudo mv sentra /usr/local/bin/
```

## Platform-Specific Instructions

### Windows

1. **Download**: Get `sentra-windows-amd64.exe` from releases
2. **Rename**: Rename to `sentra.exe`
3. **Move**: Place in a folder like `C:\tools\sentra\`
4. **Add to PATH**: 
   - Open System Properties → Environment Variables
   - Add `C:\tools\sentra` to your PATH

Or using PowerShell:
```powershell
# Download and install
Invoke-WebRequest -Uri "https://github.com/sentra-language/sentra/releases/latest/download/sentra-windows-amd64.exe" -OutFile "sentra.exe"
Move-Item sentra.exe C:\tools\sentra\
# Add to PATH manually through System Properties
```

### macOS

```bash
# Using Homebrew (when available)
brew install sentra-language/tap/sentra

# Or download binary
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-macos-amd64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/

# For Apple Silicon Macs
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-macos-arm64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/
```

### Linux

#### Ubuntu/Debian
```bash
# Download and install
wget https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -O sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/

# Or add to ~/.local/bin for user installation
mkdir -p ~/.local/bin
mv sentra ~/.local/bin/
# Add ~/.local/bin to PATH in ~/.bashrc or ~/.zshrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

#### CentOS/RHEL/Fedora
```bash
# Download
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/
```

#### Arch Linux
```bash
# Install from AUR (when available)
yay -S sentra

# Or manual installation
wget https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -O sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/
```

## Verify Installation

After installation, verify Sentra is working:

```bash
# Check version
sentra --version

# Run a simple test
echo 'log("Hello, Sentra!")' | sentra run -

# Check available commands
sentra --help
```

Expected output:
```
Sentra Programming Language v1.0.0
Built with Go 1.21
```

## IDE and Editor Support

### Visual Studio Code
Install the Sentra Language Extension:
1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Sentra Language Support"
4. Install the extension

### Vim/Neovim
```bash
# Install vim plugin
git clone https://github.com/sentra-language/vim-sentra ~/.vim/bundle/vim-sentra
```

### Emacs
```elisp
;; Add to your .emacs or init.el
(use-package sentra-mode
  :ensure t
  :mode "\\.sn\\'")
```

## Development Environment Setup

### Create First Project
```bash
# Initialize a new Sentra project
sentra init my-first-project
cd my-first-project

# Project structure
ls -la
# .
# ├── main.sn          # Entry point
# ├── sentra.toml       # Project configuration
# ├── src/              # Source files
# └── tests/            # Test files
```

### Configure Your Environment
Create a `sentra.toml` in your project:

```toml
[package]
name = "my-app"
version = "1.0.0"
description = "My Sentra application"
author = "Your Name <email@example.com>"

[dependencies]
# Add dependencies here when available

[build]
target = "."
output = "dist/"

[test]
directory = "tests/"
pattern = "*.test.sn"
```

## Troubleshooting

### Common Issues

**1. Command not found**
```bash
# Check if Sentra is in PATH
which sentra
echo $PATH

# If not found, add to PATH
export PATH="$PATH:/path/to/sentra"
```

**2. Permission denied (Linux/macOS)**
```bash
# Make executable
chmod +x sentra

# Check permissions
ls -la sentra
```

**3. "Cannot execute binary file" (Linux)**
This means you downloaded the wrong architecture. Download the correct one:
- For 64-bit Intel/AMD: `sentra-linux-amd64`
- For ARM64: `sentra-linux-arm64`

**4. Windows antivirus blocking**
Some antivirus software may flag the binary. Add an exception for the Sentra executable.

### Getting Help

If you encounter issues:
1. Check the [FAQ](/faq)
2. Search [GitHub Issues](https://github.com/sentra-language/sentra/issues)
3. Ask on [GitHub Discussions](https://github.com/sentra-language/sentra/discussions)
4. Join our [Discord Community](https://discord.gg/sentra)

## Next Steps

Now that Sentra is installed:
1. [Write your first program]({{ site.baseurl }}/tutorial/first-program)
2. [Learn the language basics]({{ site.baseurl }}/tutorial/language-basics)
3. [Explore network programming]({{ site.baseurl }}/tutorial/network-programming)

## Updating Sentra

To update to the latest version:

```bash
# Check current version
sentra --version

# Download and replace with new version
# (repeat installation steps with latest release)

# Or if using package manager
brew upgrade sentra  # macOS with Homebrew
yay -Syu sentra     # Arch Linux with AUR
```

## Uninstalling

To remove Sentra:

```bash
# Remove binary
sudo rm /usr/local/bin/sentra

# Remove VS Code extension
code --uninstall-extension sentra-language.sentra

# Remove project files (optional)
rm -rf ~/.sentra
```

---

{: .fs-6 .fw-300 }
Next, let's write your first Sentra program and learn the basic syntax.

[Next: Your First Program →](../first-program/){: .btn .btn-primary }