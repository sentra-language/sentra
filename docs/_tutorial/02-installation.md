---
layout: tutorial
title: Installing Sentra
permalink: /tutorial/installation/
order: 2
---

# Installing Sentra

This guide will walk you through installing Sentra on your system. Choose the installation method that best fits your needs.

## Quick Install (Recommended)

### Windows

```powershell
# Download installer
Invoke-WebRequest -Uri "https://github.com/sentra-language/sentra/releases/latest/download/sentra-installer.exe" -OutFile "sentra-installer.exe"

# Run installer
.\sentra-installer.exe

# Verify installation
sentra --version
```

### macOS

```bash
# Using Homebrew (coming soon)
brew install sentra

# Or download directly
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-darwin-amd64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/

# Verify installation
sentra --version
```

### Linux

```bash
# Download latest release
curl -L https://github.com/sentra-language/sentra/releases/latest/download/sentra-linux-amd64 -o sentra
chmod +x sentra
sudo mv sentra /usr/local/bin/

# Verify installation
sentra --version
```

## Building from Source

If you prefer to build Sentra from source or want the latest development version:

### Prerequisites

- Go 1.20 or higher
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/sentra-language/sentra.git
cd sentra

# Build the interpreter
go build -o sentra ./cmd/sentra

# Optional: Install globally
sudo mv sentra /usr/local/bin/  # Unix-like systems
# OR
move sentra.exe C:\Windows\System32\  # Windows

# Verify installation
sentra --version
```

## Development Setup

For Sentra language development:

```bash
# Clone repository
git clone https://github.com/sentra-language/sentra.git
cd sentra

# Enable development mode
./dev.sh enable

# Build and install
./dev.sh build
./dev.sh install

# Run tests
./dev.sh test
```

## Verifying Your Installation

After installation, verify everything is working:

```bash
# Check version
sentra --version

# Run interactive REPL
sentra repl

# In the REPL, try:
>>> log("Hello, Sentra!")
Hello, Sentra!
>>> exit
```

## Your First Sentra Program

Create a file named `hello.sn`:

```sentra
// hello.sn
log("Hello, World!")
log("Welcome to Sentra!")

// Basic math
let result = 2 + 2
log("2 + 2 = " + str(result))

// Using security features
import security

let hash = security.sha256("Hello, Sentra!")
log("SHA256 hash: " + hash)
```

Run your program:

```bash
sentra run hello.sn
```

Expected output:
```
Hello, World!
Welcome to Sentra!
2 + 2 = 4
SHA256 hash: 7c4a8d09ca3762af61e59520943dc26494f8941b...
```

## Project Structure

Create a new Sentra project:

```bash
# Initialize a new project
sentra init my-security-app
cd my-security-app

# Project structure
my-security-app/
├── main.sn           # Entry point
├── sentra.json       # Project manifest
├── lib/              # Libraries
├── tests/            # Test files
└── README.md         # Documentation
```

## Editor Support

Sentra works with any text editor, but we recommend:

- **VS Code**: Install the Sentra extension (coming soon)
- **Vim/Neovim**: Use the sentra.vim plugin
- **Sublime Text**: Install Sentra syntax highlighting
- **IntelliJ IDEA**: Use the Sentra plugin

## Troubleshooting

### Command Not Found

If `sentra` command is not found:

**Windows:**
- Add Sentra to your PATH environment variable
- Restart your terminal

**Unix-like systems:**
```bash
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

### Permission Denied

On Unix-like systems:
```bash
chmod +x sentra
sudo mv sentra /usr/local/bin/
```

### Build Errors

Ensure Go is installed:
```bash
go version  # Should be 1.20 or higher
```

## Next Steps

Congratulations! You've successfully installed Sentra. Now let's write your first real program.

---

<div class="tutorial-nav">
    <a href="/tutorial/introduction/" class="nav-prev">← Introduction</a>
    <a href="/tutorial/first-program/" class="nav-next">Your First Program →</a>
</div>