#!/bin/bash
# test_fuzz.sh - Test fuzzing functionality against safe targets
# Usage: ./scripts/test_fuzz.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       PAYLOAD FORGE - FUZZING TEST SCRIPT            ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if binary exists
if [ ! -f "./bin/forge" ]; then
    echo -e "${RED}❌ Binary not found. Building...${NC}"
    make build
fi

echo -e "${GREEN}🎯 Testing Fuzzing Engine${NC}"
echo ""

# Test 1: Simple GET parameter fuzzing
echo -e "${CYAN}Test 1: GET Parameter Fuzzing${NC}"
echo "Target: https://httpbin.org/get?test=FUZZ"
echo ""

./bin/forge fuzz \
    --target "https://httpbin.org/get?test=FUZZ" \
    --method GET \
    --iterations 50 \
    --complexity 3 \
    2>&1 | head -30

echo ""
echo -e "${GREEN}✅ Test 1 Complete${NC}"
echo ""

# Test 2: POST parameter fuzzing
echo -e "${CYAN}Test 2: POST Parameter Fuzzing${NC}"
echo "Target: https://httpbin.org/post?data=FUZZ"
echo ""

./bin/forge fuzz \
    --target "https://httpbin.org/post?data=FUZZ" \
    --method POST \
    --iterations 20 \
    --complexity 5 \
    2>&1 | head -30

echo ""
echo -e "${GREEN}✅ Test 2 Complete${NC}"
echo ""

# Test 3: High complexity fuzzing
echo -e "${CYAN}Test 3: High Complexity Fuzzing${NC}"
echo "Target: https://httpbin.org/anything?param=FUZZ"
echo ""

./bin/forge fuzz \
    --target "https://httpbin.org/anything?param=FUZZ" \
    --method GET \
    --iterations 30 \
    --complexity 8 \
    2>&1 | head -30

echo ""
echo -e "${GREEN}✅ Test 3 Complete${NC}"
echo ""

# Summary
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✨ All Fuzzing Tests Complete!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}💡 Tips:${NC}"
echo "  • Use --iterations to control number of inputs"
echo "  • Use --complexity (1-10) to adjust sophistication"
echo "  • Replace FUZZ placeholder in target URL"
echo "  • Use --verbose for detailed logging"
echo ""
echo -e "${YELLOW}⚠️  Remember: Only test authorized targets!${NC}"
echo ""
