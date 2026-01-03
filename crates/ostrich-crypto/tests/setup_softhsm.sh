#!/usr/bin/env bash
# Setup script for SoftHSM testing environment
#
# NIST 800-53: CA-8 - Penetration testing (test environment setup)

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== OstrichPKI SoftHSM Test Environment Setup ===${NC}\n"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo -e "Detected OS: ${GREEN}${MACHINE}${NC}\n"

# Check if SoftHSM is installed
echo -e "${YELLOW}Checking for SoftHSM installation...${NC}"
if command -v softhsm2-util &> /dev/null; then
    SOFTHSM_VERSION=$(softhsm2-util --version | head -n1)
    echo -e "${GREEN}✓ SoftHSM found: ${SOFTHSM_VERSION}${NC}"
else
    echo -e "${RED}✗ SoftHSM not found${NC}"
    echo ""
    echo "Please install SoftHSM:"
    if [[ "$MACHINE" == "Mac" ]]; then
        echo "  brew install softhsm"
    elif [[ "$MACHINE" == "Linux" ]]; then
        echo "  Ubuntu/Debian: sudo apt-get install softhsm2"
        echo "  RHEL/CentOS:   sudo yum install softhsm"
        echo "  Fedora:        sudo dnf install softhsm"
    fi
    exit 1
fi

# Find SoftHSM library path
echo -e "\n${YELLOW}Locating SoftHSM library...${NC}"
SOFTHSM_LIB=""
POSSIBLE_PATHS=(
    "/usr/local/lib/softhsm/libsofthsm2.so"
    "/opt/homebrew/lib/softhsm/libsofthsm2.so"
    "/usr/lib/softhsm/libsofthsm2.so"
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    "/usr/lib64/pkcs11/libsofthsm2.so"
)

for path in "${POSSIBLE_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        SOFTHSM_LIB="$path"
        echo -e "${GREEN}✓ Found SoftHSM library: ${SOFTHSM_LIB}${NC}"
        break
    fi
done

if [[ -z "$SOFTHSM_LIB" ]]; then
    echo -e "${RED}✗ SoftHSM library not found in common locations${NC}"
    echo ""
    echo "Please find your SoftHSM library and set PKCS11_MODULE_PATH:"
    echo "  export PKCS11_MODULE_PATH=/path/to/libsofthsm2.so"
    exit 1
fi

# Initialize SoftHSM token directory
echo -e "\n${YELLOW}Configuring SoftHSM token directory...${NC}"
SOFTHSM_CONF="${HOME}/.config/softhsm2/softhsm2.conf"
SOFTHSM_TOKENS="${HOME}/.config/softhsm2/tokens"

mkdir -p "$(dirname "$SOFTHSM_CONF")"
mkdir -p "$SOFTHSM_TOKENS"

cat > "$SOFTHSM_CONF" <<EOF
# SoftHSM v2 configuration file for OstrichPKI testing
directories.tokendir = ${SOFTHSM_TOKENS}
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

echo -e "${GREEN}✓ Created SoftHSM configuration: ${SOFTHSM_CONF}${NC}"
echo -e "${GREEN}✓ Token directory: ${SOFTHSM_TOKENS}${NC}"

export SOFTHSM2_CONF="$SOFTHSM_CONF"

# List existing tokens
echo -e "\n${YELLOW}Checking for existing tokens...${NC}"
softhsm2-util --show-slots

# Check if OstrichPKI-Test token already exists
if softhsm2-util --show-slots | grep -q "OstrichPKI-Test"; then
    echo -e "\n${YELLOW}Token 'OstrichPKI-Test' already exists.${NC}"
    read -p "Do you want to delete and reinitialize it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Find slot with OstrichPKI-Test token
        SLOT=$(softhsm2-util --show-slots | grep -B 3 "OstrichPKI-Test" | grep "Slot " | awk '{print $2}')
        echo -e "${YELLOW}Deleting token in slot ${SLOT}...${NC}"
        softhsm2-util --delete-token --token "OstrichPKI-Test"
        echo -e "${GREEN}✓ Token deleted${NC}"
    else
        echo -e "${GREEN}Keeping existing token${NC}"
        echo ""
        echo "To run tests, set the environment variable:"
        echo "  export PKCS11_MODULE_PATH=${SOFTHSM_LIB}"
        echo ""
        echo "Then run tests with:"
        echo "  cargo test --test pkcs11_integration_test -- --test-threads=1"
        exit 0
    fi
fi

# Initialize new token
echo -e "\n${YELLOW}Initializing new SoftHSM token...${NC}"
echo "Token Label: OstrichPKI-Test"
echo "Slot:        0"
echo "SO PIN:      12345678"
echo "User PIN:    1234"
echo ""

softhsm2-util --init-token --slot 0 --label "OstrichPKI-Test" --so-pin 12345678 --pin 1234

if [[ $? -eq 0 ]]; then
    echo -e "\n${GREEN}✓ Token initialized successfully${NC}"
else
    echo -e "\n${RED}✗ Token initialization failed${NC}"
    exit 1
fi

# Display final configuration
echo -e "\n${GREEN}=== Setup Complete ===${NC}\n"
echo "SoftHSM Configuration:"
echo "  Library:     ${SOFTHSM_LIB}"
echo "  Config:      ${SOFTHSM_CONF}"
echo "  Tokens:      ${SOFTHSM_TOKENS}"
echo "  Token Label: OstrichPKI-Test"
echo "  Slot:        0"
echo "  PIN:         1234"
echo ""
echo "Environment variable to set:"
echo -e "  ${GREEN}export PKCS11_MODULE_PATH=${SOFTHSM_LIB}${NC}"
echo -e "  ${GREEN}export SOFTHSM2_CONF=${SOFTHSM_CONF}${NC}"
echo ""
echo "Add to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
echo "  echo 'export PKCS11_MODULE_PATH=${SOFTHSM_LIB}' >> ~/.bashrc"
echo "  echo 'export SOFTHSM2_CONF=${SOFTHSM_CONF}' >> ~/.bashrc"
echo ""
echo "Run tests with:"
echo "  cargo test --test pkcs11_integration_test -- --test-threads=1"
echo ""
echo -e "${YELLOW}Note: Tests must run with --test-threads=1 to prevent PKCS#11 session conflicts${NC}"
