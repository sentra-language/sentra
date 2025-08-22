#!/bin/bash

# Sentra Development Helper Tool
# For developers working on the Sentra language itself

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Print banner
print_banner() {
    echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         SENTRA DEVELOPMENT HELPER              ║${NC}"
    echo -e "${CYAN}║           For Language Developers              ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Show current status
show_status() {
    echo -e "${CYAN}Current Development Status:${NC}"
    echo ""
    
    if [ -n "$SENTRA_DEV_PATH" ]; then
        echo -e "${GREEN}✓ Dev mode: ENABLED${NC}"
        echo -e "  Path: $SENTRA_DEV_PATH"
    else
        echo -e "${YELLOW}⚠ Dev mode: DISABLED${NC}"
        echo -e "  Using: ~/.sentra (production)"
    fi
    
    if [ -f "./sentra" ]; then
        echo -e "${GREEN}✓ Local binary: EXISTS${NC}"
    else
        echo -e "${RED}✗ Local binary: MISSING${NC}"
        echo -e "  Run: ${YELLOW}./dev.sh build${NC}"
    fi
    
    echo ""
}

# Enable development mode
enable_dev() {
    export SENTRA_DEV_PATH="$(pwd)"
    echo "export SENTRA_DEV_PATH=\"$(pwd)\"" >> ~/.zshrc 2>/dev/null || echo "export SENTRA_DEV_PATH=\"$(pwd)\"" >> ~/.bashrc
    
    echo -e "${GREEN}✅ Development mode ENABLED${NC}"
    echo -e "  Path: $(pwd)"
    echo -e "  Added to shell config"
    echo ""
    echo -e "${CYAN}Now run:${NC} ./dev.sh install"
}

# Disable development mode
disable_dev() {
    unset SENTRA_DEV_PATH
    sed -i '' '/SENTRA_DEV_PATH/d' ~/.zshrc 2>/dev/null || sed -i '/SENTRA_DEV_PATH/d' ~/.bashrc 2>/dev/null || true
    
    echo -e "${YELLOW}⚠ Development mode DISABLED${NC}"
    echo -e "  Removed from shell config"
    echo ""
    echo -e "${CYAN}Run:${NC} ./install.sh (to use production version)"
}

# Build local binary
build_binary() {
    echo -e "${CYAN}🔨 Building Sentra binary...${NC}"
    
    rm -f sentra
    go build -o sentra ./cmd/sentra
    
    if [ -f "./sentra" ]; then
        echo -e "${GREEN}✅ Build successful${NC}"
        echo -e "  Binary: ./sentra"
        
        # Test the binary
        VERSION=$(./sentra --version 2>/dev/null | head -1 || echo "Unknown")
        echo -e "  Version: $VERSION"
    else
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
}

# Install in development mode
install_dev() {
    if [ -z "$SENTRA_DEV_PATH" ]; then
        echo -e "${RED}❌ Development mode not enabled${NC}"
        echo -e "  Run: ${YELLOW}./dev.sh enable${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}📦 Installing in development mode...${NC}"
    ./install.sh
}

# Quick test
quick_test() {
    echo -e "${CYAN}🧪 Running quick test...${NC}"
    
    # Build if needed
    if [ ! -f "./sentra" ]; then
        build_binary
    fi
    
    # Create test project
    rm -rf dev-test
    ./sentra init dev-test
    cd dev-test
    
    echo -e "${CYAN}Testing main.sn...${NC}"
    ../sentra run main.sn
    
    echo -e "${CYAN}Testing test suite...${NC}"
    ../sentra test
    
    cd ..
    rm -rf dev-test
    
    echo -e "${GREEN}✅ Quick test passed${NC}"
}

# Show usage
show_usage() {
    echo "Sentra Development Helper"
    echo ""
    echo "Usage: ./dev.sh <command>"
    echo ""
    echo "Commands:"
    echo "  status    Show current development status"
    echo "  enable    Enable development mode"
    echo "  disable   Disable development mode"
    echo "  build     Build local Sentra binary"
    echo "  install   Install in development mode"
    echo "  test      Run quick test"
    echo "  help      Show this help"
    echo ""
    echo "Workflow:"
    echo "  1. ./dev.sh enable     # Enable dev mode"
    echo "  2. ./dev.sh build      # Build binary"
    echo "  3. ./dev.sh install    # Install globally"
    echo "  4. ./dev.sh test       # Test everything works"
    echo ""
}

# Main logic
case "${1:-help}" in
    status)
        print_banner
        show_status
        ;;
    enable)
        print_banner
        enable_dev
        ;;
    disable)
        print_banner
        disable_dev
        ;;
    build)
        print_banner
        build_binary
        ;;
    install)
        print_banner
        install_dev
        ;;
    test)
        print_banner
        quick_test
        ;;
    help|--help|-h)
        print_banner
        show_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac