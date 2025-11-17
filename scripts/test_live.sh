#!/bin/bash
# test_live.sh - Automated testing script for safe/legal targets
# Usage: ./scripts/test_live.sh [target_type]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       PAYLOAD FORGE - LIVE TESTING SCRIPT            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if binary exists
if [ ! -f "./bin/forge" ]; then
    echo -e "${RED}❌ Binary not found. Building...${NC}"
    make build
fi

# Target selection
TARGET_TYPE=${1:-httpbin}

case $TARGET_TYPE in
    httpbin)
        echo -e "${GREEN}🎯 Testing against HTTPBin.org (Safe, Legal)${NC}"
        TARGET="https://httpbin.org/post"
        METHOD="POST"
        ;;

    httpbin-get)
        echo -e "${GREEN}🎯 Testing against HTTPBin.org GET (Safe, Legal)${NC}"
        TARGET="https://httpbin.org/get"
        METHOD="GET"
        ;;

    webhook)
        echo -e "${YELLOW}⚠️  For webhook.site, get your URL from https://webhook.site${NC}"
        read -p "Enter your webhook.site URL: " WEBHOOK_URL
        TARGET="$WEBHOOK_URL"
        METHOD="POST"
        ;;

    local)
        echo -e "${GREEN}🎯 Testing against localhost (Safe)${NC}"
        TARGET="http://localhost:3000/rest/products/search"
        METHOD="GET"
        echo -e "${YELLOW}Make sure OWASP Juice Shop is running:${NC}"
        echo "  docker run -p 3000:3000 bkimminich/juice-shop"
        ;;

    *)
        echo -e "${RED}❌ Unknown target type: $TARGET_TYPE${NC}"
        echo ""
        echo "Available targets:"
        echo "  httpbin       - HTTPBin.org POST endpoint (default)"
        echo "  httpbin-get   - HTTPBin.org GET endpoint"
        echo "  webhook       - Webhook.site (requires URL)"
        echo "  local         - Local OWASP Juice Shop"
        echo ""
        echo "Usage: ./scripts/test_live.sh [target_type]"
        exit 1
        ;;
esac

echo ""
echo -e "${CYAN}📋 Test Configuration:${NC}"
echo "  Target:  $TARGET"
echo "  Method:  $METHOD"
echo "  Profile: sqli"
echo "  Workers: 3"
echo "  Rate:    2 req/s"
echo ""

# Run test with automatic "yes" response
echo -e "${GREEN}🚀 Starting test...${NC}"
echo ""

# Use echo to pipe "yes" to the command
echo "yes" | timeout 120s ./bin/forge test \
    --profile sqli \
    --target "$TARGET" \
    --method "$METHOD" \
    --workers 3 \
    --rate 2 \
    2>&1 | tee test_output.log

EXIT_CODE=$?

echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Test completed successfully!${NC}"

    # Check for vulnerabilities in output
    if grep -q "VULNERABILITIES FOUND" test_output.log; then
        echo -e "${YELLOW}⚠️  Vulnerabilities detected (expected for vulnerable targets)${NC}"
    else
        echo -e "${CYAN}ℹ️  No vulnerabilities found (expected for safe targets like HTTPBin)${NC}"
    fi

elif [ $EXIT_CODE -eq 124 ]; then
    echo -e "${YELLOW}⏱️  Test timed out after 120 seconds${NC}"
else
    echo -e "${RED}❌ Test failed with exit code: $EXIT_CODE${NC}"
fi

echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}📄 Full output saved to: test_output.log${NC}"
echo ""

# Show statistics if available
if grep -q "Statistics:" test_output.log; then
    echo -e "${CYAN}📊 Quick Summary:${NC}"
    grep -A 8 "Statistics:" test_output.log | sed 's/^/  /'
fi

echo ""
echo -e "${GREEN}✨ Test complete!${NC}"
