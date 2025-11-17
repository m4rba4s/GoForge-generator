#!/bin/bash
# Advanced Cloudflare WAF Testing Script
# Tests Cloudflare protection mechanisms and security headers
# LEGAL USE ONLY - Test your own infrastructure

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
TARGET=""
OUTPUT_DIR="cloudflare_test_results"
VERBOSE=false
STEALTH_MODE=true
TEST_WAF=true
TEST_HEADERS=true
TEST_RATE_LIMIT=false

# User agents for testing (realistic browser signatures)
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
)

# Cloudflare bypass techniques
BROWSER_HEADERS=(
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    "Accept-Language: en-US,en;q=0.9"
    "Accept-Encoding: gzip, deflate, br"
    "DNT: 1"
    "Connection: keep-alive"
    "Upgrade-Insecure-Requests: 1"
    "Sec-Fetch-Dest: document"
    "Sec-Fetch-Mode: navigate"
    "Sec-Fetch-Site: none"
    "Sec-Fetch-User: ?1"
    "Cache-Control: max-age=0"
)

# Usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] <TARGET_URL>

Advanced Cloudflare WAF Testing Tool

OPTIONS:
    -o, --output DIR    Output directory (default: cloudflare_test_results)
    -v, --verbose       Verbose output
    -w, --waf-only      Test WAF only
    -h, --headers-only  Test headers only
    -r, --rate-limit    Test rate limiting (careful!)
    --no-stealth        Disable stealth mode
    --help              Show this help

EXAMPLES:
    # Full test
    $0 https://yourdomain.com

    # Headers only
    $0 -h https://yourdomain.com

    # WAF test with verbose
    $0 -v -w https://yourdomain.com

LEGAL NOTICE:
    Only test domains you own or have explicit permission to test.
    Unauthorized testing is illegal.

EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -w|--waf-only)
            TEST_HEADERS=false
            TEST_WAF=true
            shift
            ;;
        -h|--headers-only)
            TEST_WAF=false
            TEST_HEADERS=true
            shift
            ;;
        -r|--rate-limit)
            TEST_RATE_LIMIT=true
            shift
            ;;
        --no-stealth)
            STEALTH_MODE=false
            shift
            ;;
        --help)
            usage
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo -e "${RED}Error: Target URL required${NC}"
    usage
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$OUTPUT_DIR/report_${TIMESTAMP}.txt"

# Banner
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}     ${MAGENTA}CLOUDFLARE WAF & SECURITY TESTING TOOL${NC}            ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Target:${NC} $TARGET"
echo -e "${BLUE}Timestamp:${NC} $TIMESTAMP"
echo -e "${BLUE}Output:${NC} $REPORT_FILE"
echo ""

# Legal confirmation
echo -e "${YELLOW}⚠️  LEGAL CONFIRMATION REQUIRED${NC}"
echo "This tool will test the target's security configuration."
echo "You must own this domain or have explicit written permission."
echo ""
read -p "Do you have authorization to test $TARGET? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo -e "${RED}Test cancelled - Authorization not confirmed${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Authorization confirmed${NC}"
echo ""

# Initialize report
{
    echo "Cloudflare Security Test Report"
    echo "================================"
    echo "Target: $TARGET"
    echo "Date: $(date)"
    echo ""
} > "$REPORT_FILE"

# Function to make stealthy request
make_request() {
    local url=$1
    local method=${2:-GET}
    local data=${3:-}

    # Random user agent
    local ua=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}

    # Build curl command with realistic browser headers
    local curl_cmd="curl -s -i -X $method"
    curl_cmd="$curl_cmd -H 'User-Agent: $ua'"

    for header in "${BROWSER_HEADERS[@]}"; do
        curl_cmd="$curl_cmd -H '$header'"
    done

    # Add TLS settings for realistic fingerprint
    curl_cmd="$curl_cmd --tlsv1.2 --tls-max 1.3"
    curl_cmd="$curl_cmd --compressed"

    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi

    curl_cmd="$curl_cmd '$url'"

    if $VERBOSE; then
        echo -e "${BLUE}[DEBUG]${NC} $curl_cmd" >&2
    fi

    eval $curl_cmd
}

# Test 1: Basic Connectivity & Cloudflare Detection
echo -e "${CYAN}[TEST 1/5]${NC} Basic Connectivity & Cloudflare Detection"
echo ""

RESPONSE=$(make_request "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | grep -i "^HTTP" | tail -1 | awk '{print $2}')
CF_RAY=$(echo "$RESPONSE" | grep -i "CF-Ray:" | cut -d: -f2- | tr -d '[:space:]')
SERVER=$(echo "$RESPONSE" | grep -i "^Server:" | cut -d: -f2- | tr -d '[:space:]')

{
    echo "=== Test 1: Connectivity ==="
    echo "HTTP Status: $HTTP_CODE"
    echo "CF-Ray: $CF_RAY"
    echo "Server: $SERVER"
    echo ""
} >> "$REPORT_FILE"

if [ -n "$CF_RAY" ]; then
    echo -e "  ${GREEN}✓${NC} Cloudflare detected (Ray ID: $CF_RAY)"
else
    echo -e "  ${YELLOW}⚠${NC} Cloudflare not detected - site may not be protected"
fi

if [ "$HTTP_CODE" == "200" ]; then
    echo -e "  ${GREEN}✓${NC} Site accessible (HTTP $HTTP_CODE)"
elif [ "$HTTP_CODE" == "403" ] || [ "$HTTP_CODE" == "503" ]; then
    echo -e "  ${YELLOW}⚠${NC} Cloudflare challenge/block (HTTP $HTTP_CODE)"
    echo -e "  ${BLUE}→${NC} This is expected for security tools"
else
    echo -e "  ${BLUE}ℹ${NC} HTTP Status: $HTTP_CODE"
fi

echo ""

# Test 2: Security Headers Analysis
if $TEST_HEADERS; then
    echo -e "${CYAN}[TEST 2/5]${NC} Security Headers Analysis"
    echo ""

    HSTS=$(echo "$RESPONSE" | grep -i "Strict-Transport-Security:" | cut -d: -f2- | sed 's/^[[:space:]]*//')
    CSP=$(echo "$RESPONSE" | grep -i "Content-Security-Policy:" | cut -d: -f2- | sed 's/^[[:space:]]*//')
    X_CONTENT=$(echo "$RESPONSE" | grep -i "X-Content-Type-Options:" | cut -d: -f2- | sed 's/^[[:space:]]*//')
    X_FRAME=$(echo "$RESPONSE" | grep -i "X-Frame-Options:" | cut -d: -f2- | sed 's/^[[:space:]]*//')

    {
        echo "=== Test 2: Security Headers ==="
        echo "HSTS: $HSTS"
        echo "CSP: $CSP"
        echo "X-Content-Type-Options: $X_CONTENT"
        echo "X-Frame-Options: $X_FRAME"
        echo ""
    } >> "$REPORT_FILE"

    HEADER_SCORE=0
    TOTAL_HEADERS=4

    if [ -n "$HSTS" ]; then
        echo -e "  ${GREEN}✓${NC} HSTS present"
        HEADER_SCORE=$((HEADER_SCORE + 1))
    else
        echo -e "  ${RED}✗${NC} HSTS missing"
    fi

    if [ -n "$CSP" ]; then
        echo -e "  ${GREEN}✓${NC} CSP present"
        HEADER_SCORE=$((HEADER_SCORE + 1))
    else
        echo -e "  ${YELLOW}⚠${NC} CSP missing or weak"
    fi

    if [ -n "$X_CONTENT" ]; then
        echo -e "  ${GREEN}✓${NC} X-Content-Type-Options present"
        HEADER_SCORE=$((HEADER_SCORE + 1))
    else
        echo -e "  ${RED}✗${NC} X-Content-Type-Options missing"
    fi

    if [ -n "$X_FRAME" ]; then
        echo -e "  ${GREEN}✓${NC} X-Frame-Options present"
        HEADER_SCORE=$((HEADER_SCORE + 1))
    else
        echo -e "  ${RED}✗${NC} X-Frame-Options missing"
    fi

    HEADER_PERCENT=$((HEADER_SCORE * 100 / TOTAL_HEADERS))
    echo ""
    echo -e "  ${BLUE}Security Headers Score: ${HEADER_PERCENT}%${NC} ($HEADER_SCORE/$TOTAL_HEADERS)"
    echo ""
fi

# Test 3: WAF Detection with SQLi payloads
if $TEST_WAF; then
    echo -e "${CYAN}[TEST 3/5]${NC} WAF Detection (SQL Injection)"
    echo ""

    SQLI_PAYLOADS=(
        "' OR '1'='1"
        "' UNION SELECT NULL--"
        "admin' OR '1'='1'--"
        "1' AND '1'='2"
    )

    {
        echo "=== Test 3: WAF Detection ==="
    } >> "$REPORT_FILE"

    BLOCKED_COUNT=0

    for payload in "${SQLI_PAYLOADS[@]}"; do
        if $STEALTH_MODE; then
            sleep $(echo "scale=2; $RANDOM/32767 + 1" | bc)
        fi

        TEST_URL="${TARGET}?id=$(echo "$payload" | sed 's/ /%20/g' | sed "s/'/%27/g")"
        RESPONSE=$(make_request "$TEST_URL")
        STATUS=$(echo "$RESPONSE" | grep -i "^HTTP" | tail -1 | awk '{print $2}')

        {
            echo "Payload: $payload"
            echo "Status: $STATUS"
            echo ""
        } >> "$REPORT_FILE"

        if [ "$STATUS" == "403" ] || [ "$STATUS" == "406" ] || [ "$STATUS" == "503" ]; then
            echo -e "  ${GREEN}✓${NC} Blocked: $payload (HTTP $STATUS)"
            BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
        elif [ "$STATUS" == "200" ]; then
            echo -e "  ${YELLOW}⚠${NC} Allowed: $payload (HTTP $STATUS)"
        else
            echo -e "  ${BLUE}?${NC} Unknown: $payload (HTTP $STATUS)"
        fi
    done

    BLOCK_RATE=$((BLOCKED_COUNT * 100 / ${#SQLI_PAYLOADS[@]}))
    echo ""
    echo -e "  ${BLUE}WAF Block Rate: ${BLOCK_RATE}%${NC} ($BLOCKED_COUNT/${#SQLI_PAYLOADS[@]})"

    if [ $BLOCK_RATE -ge 75 ]; then
        echo -e "  ${GREEN}✓ WAF is effectively blocking SQL injection${NC}"
    elif [ $BLOCK_RATE -ge 50 ]; then
        echo -e "  ${YELLOW}⚠ WAF is partially blocking SQL injection${NC}"
    else
        echo -e "  ${RED}✗ WAF may not be properly configured${NC}"
    fi

    echo ""
fi

# Test 4: XSS Detection
if $TEST_WAF; then
    echo -e "${CYAN}[TEST 4/5]${NC} WAF Detection (XSS)"
    echo ""

    XSS_PAYLOADS=(
        "<script>alert(1)</script>"
        "<img src=x onerror=alert(1)>"
        "javascript:alert(1)"
    )

    {
        echo "=== Test 4: XSS Detection ==="
    } >> "$REPORT_FILE"

    XSS_BLOCKED=0

    for payload in "${XSS_PAYLOADS[@]}"; do
        if $STEALTH_MODE; then
            sleep $(echo "scale=2; $RANDOM/32767 + 1" | bc)
        fi

        ENCODED=$(echo "$payload" | sed 's/</\%3C/g' | sed 's/>/\%3E/g' | sed 's/ /%20/g')
        TEST_URL="${TARGET}?q=$ENCODED"
        RESPONSE=$(make_request "$TEST_URL")
        STATUS=$(echo "$RESPONSE" | grep -i "^HTTP" | tail -1 | awk '{print $2}')

        {
            echo "Payload: $payload"
            echo "Status: $STATUS"
            echo ""
        } >> "$REPORT_FILE"

        if [ "$STATUS" == "403" ] || [ "$STATUS" == "406" ] || [ "$STATUS" == "503" ]; then
            echo -e "  ${GREEN}✓${NC} Blocked: $(echo $payload | head -c 30)... (HTTP $STATUS)"
            XSS_BLOCKED=$((XSS_BLOCKED + 1))
        elif [ "$STATUS" == "200" ]; then
            echo -e "  ${YELLOW}⚠${NC} Allowed: $(echo $payload | head -c 30)... (HTTP $STATUS)"
        else
            echo -e "  ${BLUE}?${NC} Unknown: $(echo $payload | head -c 30)... (HTTP $STATUS)"
        fi
    done

    echo ""
    echo -e "  ${BLUE}XSS Block Rate: $((XSS_BLOCKED * 100 / ${#XSS_PAYLOADS[@]}))%${NC} ($XSS_BLOCKED/${#XSS_PAYLOADS[@]})"
    echo ""
fi

# Test 5: TLS/SSL Configuration
echo -e "${CYAN}[TEST 5/5]${NC} TLS/SSL Configuration"
echo ""

DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1)

if command -v openssl &> /dev/null; then
    TLS_INFO=$(echo | openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null | grep -E "Protocol|Cipher")

    {
        echo "=== Test 5: TLS Configuration ==="
        echo "$TLS_INFO"
        echo ""
    } >> "$REPORT_FILE"

    if echo "$TLS_INFO" | grep -q "TLSv1.3"; then
        echo -e "  ${GREEN}✓${NC} TLS 1.3 supported"
    elif echo "$TLS_INFO" | grep -q "TLSv1.2"; then
        echo -e "  ${GREEN}✓${NC} TLS 1.2 supported"
    else
        echo -e "  ${YELLOW}⚠${NC} Older TLS version detected"
    fi

    if echo "$TLS_INFO" | grep -q "Cipher"; then
        CIPHER=$(echo "$TLS_INFO" | grep "Cipher" | cut -d= -f2)
        echo -e "  ${BLUE}ℹ${NC} Cipher: $CIPHER"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} OpenSSL not found - TLS check skipped"
fi

echo ""

# Final Summary
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${MAGENTA}SUMMARY${NC}                              ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

{
    echo "=== Summary ==="
    echo ""
    echo "Cloudflare Status: $([ -n "$CF_RAY" ] && echo "Active" || echo "Not detected")"
    if $TEST_HEADERS; then
        echo "Security Headers: $HEADER_PERCENT%"
    fi
    if $TEST_WAF; then
        echo "WAF Block Rate (SQLi): $BLOCK_RATE%"
        echo "WAF Block Rate (XSS): $((XSS_BLOCKED * 100 / ${#XSS_PAYLOADS[@]}))%"
    fi
    echo ""
    echo "Full report: $REPORT_FILE"
} >> "$REPORT_FILE"

if [ -n "$CF_RAY" ]; then
    echo -e "${GREEN}✓${NC} Cloudflare Protection: ${GREEN}ACTIVE${NC}"
else
    echo -e "${RED}✗${NC} Cloudflare Protection: ${RED}NOT DETECTED${NC}"
fi

if $TEST_HEADERS; then
    if [ $HEADER_PERCENT -ge 75 ]; then
        echo -e "${GREEN}✓${NC} Security Headers: ${GREEN}GOOD${NC} ($HEADER_PERCENT%)"
    elif [ $HEADER_PERCENT -ge 50 ]; then
        echo -e "${YELLOW}⚠${NC} Security Headers: ${YELLOW}NEEDS IMPROVEMENT${NC} ($HEADER_PERCENT%)"
    else
        echo -e "${RED}✗${NC} Security Headers: ${RED}POOR${NC} ($HEADER_PERCENT%)"
    fi
fi

if $TEST_WAF; then
    if [ $BLOCK_RATE -ge 75 ]; then
        echo -e "${GREEN}✓${NC} WAF Effectiveness: ${GREEN}GOOD${NC} ($BLOCK_RATE%)"
    elif [ $BLOCK_RATE -ge 50 ]; then
        echo -e "${YELLOW}⚠${NC} WAF Effectiveness: ${YELLOW}MODERATE${NC} ($BLOCK_RATE%)"
    else
        echo -e "${RED}✗${NC} WAF Effectiveness: ${RED}WEAK${NC} ($BLOCK_RATE%)"
    fi
fi

echo ""
echo -e "${BLUE}Full report saved to:${NC} $REPORT_FILE"
echo ""

# Recommendations
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                ${MAGENTA}RECOMMENDATIONS${NC}                         ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ -z "$HSTS" ]; then
    echo -e "${YELLOW}→${NC} Enable HSTS in Cloudflare: SSL/TLS → Edge Certificates"
fi

if [ -z "$CSP" ]; then
    echo -e "${YELLOW}→${NC} Configure CSP via Transform Rules or Headers"
fi

if [ $BLOCK_RATE -lt 75 ]; then
    echo -e "${YELLOW}→${NC} Review WAF rules: Security → WAF → Managed Rules"
    echo -e "   Enable OWASP ModSecurity Core Rule Set"
fi

if [ -z "$CF_RAY" ]; then
    echo -e "${YELLOW}→${NC} Enable Cloudflare proxy (orange cloud) in DNS settings"
fi

echo ""
echo -e "${GREEN}✅ Test completed!${NC}"
echo ""
