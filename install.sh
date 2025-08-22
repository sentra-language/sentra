#!/bin/bash

# Sentra Programming Language - Universal Smart Installer
# One installer to rule them all - handles everything automatically
# Repository: https://github.com/sentra-language/sentra.git

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration - Support dev environments
SENTRA_REPO="${SENTRA_REPO:-https://github.com/sentra-language/sentra.git}"
SENTRA_INSTALL_DIR="${SENTRA_INSTALL_DIR:-$HOME/.sentra}"
SENTRA_BRANCH="${SENTRA_BRANCH:-main}"

# Check for dev environment
if [ -n "$SENTRA_DEV_PATH" ]; then
    echo -e "${CYAN}📦 Using development path: $SENTRA_DEV_PATH${NC}"
    SENTRA_INSTALL_DIR="$SENTRA_DEV_PATH"
fi

# Detect system
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Print banner
print_banner() {
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         SENTRA PROGRAMMING LANGUAGE            ║${NC}"
    echo -e "${CYAN}║           Universal Smart Installer            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}System: $OS ($ARCH)${NC}"
    echo ""
}

# Find and fix broken installations
fix_broken_installations() {
    echo -e "${CYAN}Scanning for broken installations...${NC}"
    
    # Check if timeout command exists, use gtimeout on macOS if needed
    TIMEOUT_CMD="timeout"
    if ! command -v timeout &> /dev/null; then
        if command -v gtimeout &> /dev/null; then
            TIMEOUT_CMD="gtimeout"
        else
            # No timeout available, create a simple function
            TIMEOUT_CMD=""
        fi
    fi
    
    # Define high-precedence paths by OS
    case "$OS" in
        "darwin")  # macOS
            HIGH_PRECEDENCE_PATHS=(
                "/usr/local/bin"
                "/opt/homebrew/bin"
            )
            ;;
        "linux")   # Linux
            HIGH_PRECEDENCE_PATHS=(
                "/usr/local/bin"
                "/usr/bin"
            )
            ;;
        *)         # Other Unix-like
            HIGH_PRECEDENCE_PATHS=(
                "/usr/local/bin"
            )
            ;;
    esac
    
    FIXED_ANY=false
    
    for path in "${HIGH_PRECEDENCE_PATHS[@]}"; do
        if [ -f "$path/sentra" ]; then
            # Check if it's broken - use timeout to prevent hanging
            IS_BROKEN=false
            
            # First check for known broken pattern
            if grep -q "sentra-universal" "$path/sentra" 2>/dev/null; then
                IS_BROKEN=true
                echo -e "${YELLOW}Found broken sentra in $path (references sentra-universal)${NC}"
            else
                # Test with timeout to prevent hanging
                if [ -n "$TIMEOUT_CMD" ]; then
                    if ! $TIMEOUT_CMD 2 "$path/sentra" --help &>/dev/null 2>&1; then
                        IS_BROKEN=true
                        echo -e "${YELLOW}Found broken sentra in $path (command failed)${NC}"
                    else
                        echo -e "${GREEN}✓ $path/sentra is working${NC}"
                    fi
                else
                    # No timeout available, skip the test
                    echo -e "${CYAN}✓ $path/sentra exists (test skipped - no timeout cmd)${NC}"
                fi
            fi
            
            if [ "$IS_BROKEN" = true ]; then
                
                # Try to fix it
                if [ -w "$path" ]; then
                    # We can write without sudo
                    echo -e "${GREEN}Fixing $path/sentra (no sudo needed)${NC}"
                    cat > "$path/sentra" << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
                    # Create sen as symlink to sentra
                    ln -sf "$path/sentra" "$path/sen"
                    chmod +x "$path/sentra" 2>/dev/null || true
                    FIXED_ANY=true
                elif sudo -n true 2>/dev/null; then
                    # sudo without password
                    echo -e "${GREEN}Fixing $path/sentra with sudo${NC}"
                    sudo bash -c "cat > $path/sentra << EOF
#!/bin/bash
exec \"$SENTRA_INSTALL_DIR/sentra\" \"\\\$@\"
EOF"
                    # Create sen as symlink to sentra
                    sudo ln -sf "$path/sentra" "$path/sen"
                    sudo chmod +x "$path/sentra" 2>/dev/null || true
                    FIXED_ANY=true
                else
                    # Need manual intervention - create temp fix
                    echo -e "${YELLOW}Creating temporary fix for $path${NC}"
                    cat > /tmp/sentra-fix << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
                    chmod +x /tmp/sentra-fix
                    
                    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    echo -e "${YELLOW}Manual fix needed for $path:${NC}"
                    echo -e "${GREEN}sudo cp /tmp/sentra-fix $path/sentra${NC}"
                    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    # Don't wait for input in non-interactive mode
                    if [ -t 0 ]; then
                        echo -e "${CYAN}Press Enter to continue...${NC}"
                        read -r
                    fi
                fi
            fi
        fi
    done
    
    if [ "$FIXED_ANY" = true ]; then
        echo -e "${GREEN}✅ Fixed broken installations${NC}"
    fi
}

# Check prerequisites
check_prerequisites() {
    echo -e "${CYAN}Checking prerequisites...${NC}"
    
    MISSING_PREREQS=false
    
    if ! command -v git &> /dev/null; then
        echo -e "${RED}❌ Git is not installed${NC}"
        MISSING_PREREQS=true
    fi
    
    if ! command -v go &> /dev/null; then
        # Try to find Go in common locations
        GO_PATHS=(
            "/usr/local/go/bin/go"
            "/opt/homebrew/bin/go"
            "/c/Program Files/Go/bin/go.exe"
            "C:/Program Files/Go/bin/go.exe"
        )
        
        GO_FOUND=false
        for go_path in "${GO_PATHS[@]}"; do
            if [ -x "$go_path" ]; then
                export PATH="$(dirname "$go_path"):$PATH"
                GO_FOUND=true
                echo -e "${GREEN}✓ Found Go at $go_path${NC}"
                break
            fi
        done
        
        if [ "$GO_FOUND" = false ]; then
            echo -e "${RED}❌ Go is not installed${NC}"
            echo -e "${YELLOW}Please install Go from: https://golang.org/dl/${NC}"
            MISSING_PREREQS=true
        fi
    else
        echo -e "${GREEN}✓ Go is installed${NC}"
    fi
    
    if [ "$MISSING_PREREQS" = true ]; then
        exit 1
    fi
    
    echo -e "${GREEN}✅ All prerequisites met${NC}"
}

# Install or update Sentra
install_sentra() {
    if [ -d "$SENTRA_INSTALL_DIR" ]; then
        echo -e "${CYAN}Found existing installation at $SENTRA_INSTALL_DIR${NC}"
        
        # Check if it's a git repo
        if [ -d "$SENTRA_INSTALL_DIR/.git" ]; then
            echo -e "${GREEN}Updating from git...${NC}"
            cd "$SENTRA_INSTALL_DIR"
            git fetch origin
            git checkout "$SENTRA_BRANCH"
            git pull origin "$SENTRA_BRANCH"
        else
            echo -e "${YELLOW}Not a git repository, rebuilding only...${NC}"
        fi
    else
        echo -e "${GREEN}Cloning Sentra repository...${NC}"
        git clone -b "$SENTRA_BRANCH" "$SENTRA_REPO" "$SENTRA_INSTALL_DIR"
    fi
    
    # Build Sentra
    echo -e "${GREEN}Building Sentra...${NC}"
    cd "$SENTRA_INSTALL_DIR"
    
    # Check if sentra exists and is a wrapper script (to avoid overwriting binary with script)
    if [ -f "sentra" ] && [ $(stat -f%z "sentra" 2>/dev/null || stat -c%s "sentra" 2>/dev/null) -lt 1000 ]; then
        echo -e "${YELLOW}Removing wrapper script before building...${NC}"
        rm -f sentra
    fi
    
    if [ "$OS" = "windows" ] || [[ "$OS" == *"mingw"* ]] || [[ "$OS" == *"msys"* ]]; then
        go build -o sentra.exe ./cmd/sentra
    else
        go build -o sentra ./cmd/sentra
        chmod +x sentra
    fi
    
    # Verify the binary is actually a binary and not a script
    if [ -f "sentra" ]; then
        FILE_SIZE=$(stat -f%z "sentra" 2>/dev/null || stat -c%s "sentra" 2>/dev/null)
        if [ "$FILE_SIZE" -lt 1000000 ]; then
            echo -e "${RED}❌ Build may have failed - binary too small ($FILE_SIZE bytes)${NC}"
            echo -e "${YELLOW}Attempting rebuild...${NC}"
            rm -f sentra
            go build -o sentra ./cmd/sentra
            chmod +x sentra
        fi
    fi
    
    echo -e "${GREEN}✅ Build successful${NC}"
}

# Setup global commands intelligently
setup_commands() {
    echo -e "${CYAN}Setting up global commands...${NC}"
    
    # First, try high-precedence paths if we can write to them
    COMMAND_INSTALLED=false
    
    for path in "${HIGH_PRECEDENCE_PATHS[@]}"; do
        if [ -d "$path" ]; then
            if [ -w "$path" ]; then
                # Direct write access
                echo -e "${GREEN}Installing to $path (no sudo needed)${NC}"
                cat > "$path/sentra" << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
                # Create sen as symlink to sentra
                ln -sf "$path/sentra" "$path/sen"
                chmod +x "$path/sentra"
                COMMAND_INSTALLED=true
                echo -e "${GREEN}✅ Commands installed to $path${NC}"
                break
            elif sudo -n true 2>/dev/null; then
                # sudo without password
                echo -e "${GREEN}Installing to $path with sudo${NC}"
                sudo bash -c "cat > $path/sentra << EOF
#!/bin/bash
exec \"$SENTRA_INSTALL_DIR/sentra\" \"\\\$@\"
EOF"
                sudo chmod +x "$path/sentra"
                COMMAND_INSTALLED=true
                echo -e "${GREEN}✅ Commands installed to $path${NC}"
                break
            fi
        fi
    done
    
    # Fallback to user's local bin
    if [ "$COMMAND_INSTALLED" = false ]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        
        cat > "$INSTALL_DIR/sentra" << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
        # Create sen as symlink to sentra
        ln -sf "$INSTALL_DIR/sentra" "$INSTALL_DIR/sen"
        chmod +x "$INSTALL_DIR/sentra"
        
        echo -e "${GREEN}✅ Commands installed to $INSTALL_DIR${NC}"
        
        # Check if it's in PATH
        if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
            echo ""
            echo -e "${YELLOW}⚠️  Add to PATH for global access:${NC}"
            echo -e "${GREEN}export PATH=\"$INSTALL_DIR:\$PATH\"${NC}"
            echo ""
            
            # Try to auto-add to shell configs
            SHELL_CONFIGS=()
            [ -f "$HOME/.bashrc" ] && SHELL_CONFIGS+=("$HOME/.bashrc")
            [ -f "$HOME/.zshrc" ] && SHELL_CONFIGS+=("$HOME/.zshrc")
            
            if [ ${#SHELL_CONFIGS[@]} -gt 0 ]; then
                echo -e "${CYAN}Add to PATH automatically? (y/n):${NC}"
                read -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    for config in "${SHELL_CONFIGS[@]}"; do
                        if ! grep -q "$INSTALL_DIR" "$config"; then
                            echo "" >> "$config"
                            echo "# Sentra Programming Language" >> "$config"
                            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$config"
                            echo -e "${GREEN}✓ Added to $config${NC}"
                        fi
                    done
                    echo -e "${CYAN}Reload your shell or run: source ~/.bashrc${NC}"
                fi
            fi
        fi
    fi
    
    # Only create convenience script if sentra binary doesn't exist
    # Never overwrite an actual compiled binary!
    if [ ! -f ./sentra ]; then
        cat > ./sentra << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
        chmod +x ./sentra
    elif [ $(stat -f%z ./sentra 2>/dev/null || stat -c%s ./sentra 2>/dev/null || echo 0) -lt 1000 ]; then
        # Only replace if it's a tiny script, not a real binary
        echo -e "${CYAN}Replacing wrapper script with updated version${NC}"
        cat > ./sentra << EOF
#!/bin/bash
exec "$SENTRA_INSTALL_DIR/sentra" "\$@"
EOF
        chmod +x ./sentra
    fi
}

# Verify installation thoroughly
verify_installation() {
    echo ""
    echo -e "${CYAN}Verifying installation...${NC}"
    
    # Check for timeout command
    TIMEOUT_CMD="timeout"
    if ! command -v timeout &> /dev/null; then
        if command -v gtimeout &> /dev/null; then
            TIMEOUT_CMD="gtimeout"
        else
            TIMEOUT_CMD=""
        fi
    fi
    
    # Test the actual binary - just check if it exists and is executable
    if [ -f "$SENTRA_INSTALL_DIR/sentra" ] && [ -x "$SENTRA_INSTALL_DIR/sentra" ]; then
        # Check file size to ensure it's a real binary
        FILE_SIZE=$(stat -f%z "$SENTRA_INSTALL_DIR/sentra" 2>/dev/null || stat -c%s "$SENTRA_INSTALL_DIR/sentra" 2>/dev/null)
        if [ "$FILE_SIZE" -gt 1000000 ]; then
            echo -e "${GREEN}✓ Sentra binary installed (${FILE_SIZE} bytes)${NC}"
        else
            echo -e "${YELLOW}⚠ Sentra binary may be incomplete (${FILE_SIZE} bytes)${NC}"
        fi
    else
        echo -e "${RED}✗ Sentra binary not found or not executable${NC}"
    fi
    
    # Test global command - just check if it's in PATH
    if command -v sentra &> /dev/null; then
        SENTRA_PATH=$(which sentra)
        echo -e "${GREEN}✓ 'sentra' command available at: $SENTRA_PATH${NC}"
    else
        echo -e "${YELLOW}⚠ 'sentra' not in PATH (use ./sentra or add to PATH)${NC}"
    fi
    
    return 0
}

# Main installation flow
main() {
    print_banner
    
    # Fix any broken installations first
    fix_broken_installations
    
    # Check prerequisites
    check_prerequisites
    
    echo -e "${CYAN}Installation settings:${NC}"
    echo -e "  Repository: $SENTRA_REPO"
    echo -e "  Branch: $SENTRA_BRANCH"
    echo -e "  Install to: $SENTRA_INSTALL_DIR"
    echo ""
    
    # Install/update Sentra
    install_sentra
    
    # Setup commands
    setup_commands
    
    # Verify everything works
    verify_installation
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}Installation Complete! 🎉${NC}"
    echo ""
    
    # Show usage based on what's available
    if command -v sentra &> /dev/null; then
        echo -e "${CYAN}You can now use:${NC}"
        echo -e "  ${YELLOW}sentra run program.sn${NC}"
        echo -e "  ${YELLOW}sentra init my-project${NC}"
        echo -e "  ${YELLOW}sentra repl${NC}"
    else
        echo -e "${CYAN}Command available:${NC}"
        echo -e "  ${YELLOW}./sentra run program.sn${NC}    # From current directory"
        echo ""
        echo -e "${CYAN}Or use full path:${NC}"
        echo -e "  ${YELLOW}$SENTRA_INSTALL_DIR/sentra run program.sn${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}Get started:${NC}"
    echo -e "  ${YELLOW}sentra --help${NC}          # Show help"
    echo -e "  ${YELLOW}sentra init my-project${NC} # Create new project"
    echo -e "  ${YELLOW}sentra repl${NC}            # Start REPL"
    echo ""
    echo -e "${CYAN}Happy coding with Sentra! 🔥${NC}"
}

# Uninstall function
uninstall() {
    echo -e "${YELLOW}Uninstalling Sentra...${NC}"
    
    # Remove installation directory
    if [ -d "$SENTRA_INSTALL_DIR" ]; then
        rm -rf "$SENTRA_INSTALL_DIR"
        echo -e "${GREEN}✓ Removed $SENTRA_INSTALL_DIR${NC}"
    fi
    
    # Remove commands from all possible locations
    PATHS_TO_CLEAN=(
        "/usr/local/bin"
        "/opt/homebrew/bin"
        "$HOME/.local/bin"
        "/usr/bin"
    )
    
    for path in "${PATHS_TO_CLEAN[@]}"; do
        if [ -f "$path/sentra" ]; then
            if [ -w "$path" ]; then
                rm -f "$path/sentra"
                echo -e "${GREEN}✓ Removed from $path${NC}"
            elif sudo -n true 2>/dev/null; then
                sudo rm -f "$path/sentra"
                echo -e "${GREEN}✓ Removed from $path (sudo)${NC}"
            else
                echo -e "${YELLOW}Manual removal needed:${NC}"
                echo -e "${GREEN}sudo rm -f $path/sentra${NC}"
            fi
        fi
    done
    
    # Remove from current directory
    rm -f ./sentra
    
    echo -e "${GREEN}✅ Sentra uninstalled${NC}"
}

# Handle command line arguments
case "${1:-install}" in
    install)
        main
        ;;
    update)
        SENTRA_BRANCH="${2:-main}"
        main
        ;;
    fix)
        print_banner
        fix_broken_installations
        verify_installation
        ;;
    uninstall)
        uninstall
        ;;
    *)
        echo "Usage: $0 {install|update [branch]|fix|uninstall}"
        echo ""
        echo "  install    - Install Sentra (default)"
        echo "  update     - Update to latest version"
        echo "  fix        - Fix broken installations only"
        echo "  uninstall  - Remove Sentra completely"
        exit 1
        ;;
esac