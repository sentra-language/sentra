#!/bin/bash

echo "Installing Sentra VSCode Extension..."
echo

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "ERROR: npm is not installed. Please install Node.js first."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
npm install

# Compile TypeScript
echo "Compiling extension..."
npm run compile

# Package extension
echo "Packaging extension..."
npx vsce package

# Install extension
echo "Installing extension to VSCode..."
for vsix in *.vsix; do
    code --install-extension "$vsix"
    echo "Extension installed: $vsix"
done

echo
echo "Installation complete!"
echo "Please restart VSCode to activate the Sentra extension."