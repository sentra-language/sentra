---
layout: default
title: Installing Sentra
permalink: /installing/
---

# Installing Sentra

Choose your operating system to get started with Sentra.

<div class="install-grid">
  <div class="install-card">
    <div class="os-icon">
      <svg viewBox="0 0 88 88" width="48" height="48">
        <path fill="#0078d4" d="M0 12.5l35.7-4.9v34.5H0M40 7.3L87.3 0v41.8H40M0 45.74h35.7v34.6L0 75.34M40 46.2h47.3v41.4L40 80.9"/>
      </svg>
    </div>
    <h3>Windows</h3>
    <p>Windows 10 or later</p>
    <a href="/installing/windows/" class="btn btn-primary">Install on Windows</a>
  </div>
  
  <div class="install-card">
    <div class="os-icon">
      <svg viewBox="0 0 88 88" width="48" height="48">
        <path fill="#000" d="M73.8 15.4c-1.7-1.9-7.6-5.1-16.1-5.1-8.4 0-14 3.9-17.7 7.2-3.2 2.8-5.1 4.5-8.3 4.5-3.4 0-5.4-1.7-8.7-4.5C19.3 14.2 13.6 10.3 5.2 10.3c0 0 0 7.7 0 7.7 3.4 0 5.4 1.7 8.7 4.5 3.7 3.3 9.4 7.2 17.8 7.2 8.4 0 14-3.9 17.7-7.2 3.2-2.8 5.1-4.5 8.3-4.5 3.2 0 5.1 1.7 8.3 4.5 3.7 3.3 9.3 7.2 17.7 7.2V22c-3.2 0-5.1-1.7-8.3-4.5l-.6-2.1zM31.7 37.4c-8.4 0-14 3.9-17.7 7.2-3.2 2.8-5.1 4.5-8.3 4.5v7.7c8.4 0 14-3.9 17.7-7.2 3.2-2.8 5.1-4.5 8.3-4.5 3.2 0 5.1 1.7 8.3 4.5 3.7 3.3 9.3 7.2 17.7 7.2s14-3.9 17.7-7.2c3.2-2.8 5.1-4.5 8.3-4.5v-7.7c-8.4 0-14 3.9-17.7 7.2-3.2 2.8-5.1 4.5-8.3 4.5-3.2 0-5.1-1.7-8.3-4.5-3.7-3.3-9.3-7.2-17.7-7.2zM31.7 57.7c-8.4 0-14 3.9-17.7 7.2-3.2 2.8-5.1 4.5-8.3 4.5v7.7c8.4 0 14-3.9 17.7-7.2 3.2-2.8 5.1-4.5 8.3-4.5 3.2 0 5.1 1.7 8.3 4.5 3.7 3.3 9.3 7.2 17.7 7.2s14-3.9 17.7-7.2c3.2-2.8 5.1-4.5 8.3-4.5v-7.7c-8.4 0-14 3.9-17.7 7.2-3.2 2.8-5.1 4.5-8.3 4.5-3.2 0-5.1-1.7-8.3-4.5-3.7-3.3-9.3-7.2-17.7-7.2z"/>
      </svg>
    </div>
    <h3>macOS</h3>
    <p>macOS 10.15 or later</p>
    <a href="/installing/macos/" class="btn btn-primary">Install on macOS</a>
  </div>
  
  <div class="install-card">
    <div class="os-icon">
      <svg viewBox="0 0 88 88" width="48" height="48">
        <path fill="#f0b90b" d="M44 0C19.7 0 0 19.7 0 44s19.7 44 44 44 44-19.7 44-44S68.3 0 44 0zm0 83.8C22 83.8 4.2 66 4.2 44S22 4.2 44 4.2 83.8 22 83.8 44 66 83.8 44 83.8zm19.4-58.5c-4.8-4.8-11.3-7.5-18.1-7.5-14.1 0-25.6 11.5-25.6 25.6 0 7.5 3.2 14.2 8.3 18.9l-3.1 3.1c-6-5.5-9.7-13.4-9.7-22.2 0-16.6 13.5-30.1 30.1-30.1 8 0 15.6 3.1 21.3 8.8l-3.2 3.4zm-18.1 7.5c7.3 0 13.2 5.9 13.2 13.2s-5.9 13.2-13.2 13.2S32.1 53.3 32.1 46s5.9-13.2 13.2-13.2z"/>
      </svg>
    </div>
    <h3>Linux</h3>
    <p>Ubuntu, Debian, Fedora, etc.</p>
    <a href="/installing/linux/" class="btn btn-primary">Install on Linux</a>
  </div>
  
  <div class="install-card">
    <div class="os-icon">
      <svg viewBox="0 0 88 88" width="48" height="48">
        <path fill="#333" d="M44 8L8 26v36l36 18 36-18V26L44 8zm0 8.5L68 28.5v24L44 64.5 20 52.5v-24L44 16.5z"/>
      </svg>
    </div>
    <h3>From Source</h3>
    <p>Build from source code</p>
    <a href="/installing/source/" class="btn btn-secondary">Build from Source</a>
  </div>
</div>

## System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.15+, Linux (kernel 3.10+)
- **RAM**: 512 MB
- **Disk**: 100 MB
- **CPU**: x86-64 or ARM64

### Recommended Requirements
- **RAM**: 2 GB or more
- **Disk**: 500 MB (for development)
- **CPU**: Multi-core processor

## Installation Methods

### Quick Install (Recommended)

The fastest way to get started:

```bash
# Universal installer (detects OS automatically)
curl -sSL https://install.sentra-lang.org | sh
```

### Package Managers

<div class="package-grid">
  <div class="package-item">
    <h4>Homebrew (macOS/Linux)</h4>
    <pre><code>brew install sentra</code></pre>
  </div>
  
  <div class="package-item">
    <h4>APT (Debian/Ubuntu)</h4>
    <pre><code>sudo apt install sentra</code></pre>
  </div>
  
  <div class="package-item">
    <h4>YUM (Fedora/RHEL)</h4>
    <pre><code>sudo yum install sentra</code></pre>
  </div>
  
  <div class="package-item">
    <h4>Snap (Universal)</h4>
    <pre><code>snap install sentra</code></pre>
  </div>
  
  <div class="package-item">
    <h4>Chocolatey (Windows)</h4>
    <pre><code>choco install sentra</code></pre>
  </div>
  
  <div class="package-item">
    <h4>Scoop (Windows)</h4>
    <pre><code>scoop install sentra</code></pre>
  </div>
</div>

### Docker

Run Sentra in a container:

```bash
# Pull the latest image
docker pull sentra/sentra:latest

# Run interactively
docker run -it sentra/sentra:latest repl

# Run a script
docker run -v $(pwd):/workspace sentra/sentra:latest run /workspace/script.sn
```

### Cloud Platforms

<div class="cloud-grid">
  <div class="cloud-item">
    <h4>AWS CloudShell</h4>
    <p>Pre-installed in AWS CloudShell</p>
  </div>
  
  <div class="cloud-item">
    <h4>Google Cloud Shell</h4>
    <p>Available via Cloud Shell</p>
  </div>
  
  <div class="cloud-item">
    <h4>Azure Cloud Shell</h4>
    <p>Included in Azure CLI</p>
  </div>
  
  <div class="cloud-item">
    <h4>GitHub Codespaces</h4>
    <p>Available as extension</p>
  </div>
</div>

## Verify Installation

After installation, verify Sentra is working:

```bash
# Check version
sentra --version

# Run the REPL
sentra repl

# Run a simple program
echo 'log("Hello, Sentra!")' | sentra run -
```

## IDE Support

Enhance your development experience with IDE extensions:

- **VS Code**: [Sentra Extension](https://marketplace.visualstudio.com/items?itemName=sentra.sentra-vscode)
- **IntelliJ**: [Sentra Plugin](https://plugins.jetbrains.com/plugin/sentra)
- **Vim/Neovim**: [sentra.vim](https://github.com/sentra-language/sentra.vim)
- **Sublime Text**: [Sentra Package](https://packagecontrol.io/packages/Sentra)
- **Atom**: [language-sentra](https://atom.io/packages/language-sentra)

## Development Tools

For Sentra development:

```bash
# Install development version
git clone https://github.com/sentra-language/sentra.git
cd sentra
./dev.sh enable

# Install language server
sentra install --lsp

# Install formatter
sentra install --formatter

# Install linter
sentra install --linter
```

## Troubleshooting

### Common Issues

<details>
<summary><strong>Command not found</strong></summary>

Add Sentra to your PATH:

**Linux/macOS:**
```bash
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

**Windows:**
Add `C:\Program Files\Sentra\bin` to System PATH in Environment Variables.
</details>

<details>
<summary><strong>Permission denied</strong></summary>

Make the binary executable:
```bash
chmod +x /usr/local/bin/sentra
```
</details>

<details>
<summary><strong>Version conflicts</strong></summary>

Uninstall old version first:
```bash
sentra uninstall
# Then reinstall
```
</details>

## Updating Sentra

Keep Sentra up to date:

```bash
# Check for updates
sentra update --check

# Update to latest version
sentra update

# Update to specific version
sentra update --version 1.0.0
```

## Uninstalling

To remove Sentra:

```bash
# Using the installer
sentra uninstall

# Manual removal
rm -rf /usr/local/bin/sentra
rm -rf ~/.sentra
```

## Next Steps

After installation:

1. [Follow the Tutorial](/tutorial/) - Learn Sentra basics
2. [Read the Quick Start](/tutorial/first-program/) - Write your first program
3. [Explore Examples](https://github.com/sentra-language/examples) - See Sentra in action
4. [Join the Community](https://github.com/sentra-language/sentra/discussions) - Get help and share

## Support

Need help installing?

- [Installation FAQ](/faq/#installation)
- [GitHub Issues](https://github.com/sentra-language/sentra/issues)
- [Community Forum](https://github.com/sentra-language/sentra/discussions)

---

<div class="install-nav">
    <a href="/" class="nav-home">← Home</a>
    <a href="/tutorial/" class="nav-next">Start Tutorial →</a>
</div>