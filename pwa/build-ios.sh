#!/bin/bash
# Build script for iOS .ipa
# Run on macOS with Xcode installed

set -e

echo "🚀 Building TOTP Authenticator for iOS..."

# Check requirements
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Install: brew install node@22"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo "❌ Xcode not found. Install from App Store"
    exit 1
fi

# Check Node version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 22 ]; then
    echo "⚠️  Node.js 22+ recommended (current: $(node --version))"
    echo "Install: nvm install 22 && nvm use 22"
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Initialize Capacitor if needed
if [ ! -d "ios" ]; then
    echo "🍎 Adding iOS platform..."
    npx cap add ios
fi

# Sync web code
echo "🔄 Syncing web code..."
npx cap sync ios

# Check signing
echo "⚠️  IMPORTANT: Open Xcode and configure Signing & Capabilities"
echo "   Run: npx cap open ios"
echo ""
echo "   Then:"
echo "   1. Select project → Signing & Capabilities"
echo "   2. Choose your Team"
echo "   3. Select target device (or Generic iOS Device for .ipa)"
echo "   4. Press Cmd+Shift+K to clean, then Cmd+B to build"
echo ""

# Offer to open Xcode
read -p "Open Xcode now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    npx cap open ios
fi

echo "✅ Setup complete!"
echo ""
echo "To build .ipa:"
echo "  1. Xcode → Product → Archive"
echo "  2. Window → Organizer → Distribute App"
echo ""
echo "To run on device:"
echo "  1. Connect iPhone"
echo "  2. Xcode → Product → Destination → Your iPhone"
echo "  3. Press ▶️ Run"
