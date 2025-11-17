#!/bin/bash
# Security Headers Checker for Cloudflare-protected sites
# Checks all critical security headers and Cloudflare configuration

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Score tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNINGS=0
FAILURES=0

# Target URL
TARGET=""

# Output file
OUTPUT_FILE=""

# Usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] <URL>

Security Headers Checker - Audit HTTP security headers

OPTIONS:
    -o, --output FILE   Save results to file
    -v, --verbose       Verbose output
    -h, --help          Show this help

EXAMPLES:
    # Check single domain
    $0 https://example.com

    # Check with output file
    $0 -o report.txt https://example.com

    # Check Red Patron
    $0 https://redpatron.com

EOF
    exit 1
}

# Parse arguments
VERBOSE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
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

# Banner
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}        ${MAGENTA}SECURITY HEADERS CHECKER${NC}                         ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}        Cloudflare Configuration Audit                   ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Target:${NC} $TARGET"
echo -e "${BLUE}Date:${NC} $(date)"
echo ""

# Function to check header
check_header() {
    local header_name=$1
    local header_value=$2
    local required=$3
    local expected_value=$4
    local description=$5

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    if [ -z "$header_value" ]; then
        if [ "$required" = "true" ]; then
            echo -e "  ${RED}✗ MISSING${NC} $header_name"
            echo -e "    ${YELLOW}→${NC} $description"
            FAILURES=$((FAILURES + 1))
        else
            echo -e "  ${YELLOW}⚠ OPTIONAL${NC} $header_name (not present)"
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        if [ -n "$expected_value" ]; then
            if [[ "$header_value" == *"$expected_value"* ]]; then
                echo -e "  ${GREEN}✓ PASS${NC} $header_name"
                if $VERBOSE; then
                    echo -e "    ${CYAN}→${NC} $header_value"
                fi
                PASSED_CHECKS=$((PASSED_CHECKS + 1))
            else
                echo -e "  ${YELLOW}⚠ WEAK${NC} $header_name"
                echo -e "    ${CYAN}Found:${NC} $header_value"
                echo -e "    ${CYAN}Expected:${NC} $expected_value"
                WARNINGS=$((WARNINGS + 1))
            fi
        else
            echo -e "  ${GREEN}✓ PRESENT${NC} $header_name"
            if $VERBOSE; then
                echo -e "    ${CYAN}→${NC} $header_value"
            fi
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        fi
    fi
}

# Fetch headers
echo -e "${CYAN}[1/5]${NC} Fetching HTTP headers..."
echo ""

HEADERS=$(curl -sI -L "$TARGET" 2>&1)

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to fetch headers from $TARGET${NC}"
    exit 1
fi

# Extract individual headers (case-insensitive)
extract_header() {
    echo "$HEADERS" | grep -i "^$1:" | cut -d: -f2- | sed 's/^[[:space:]]*//' | tr -d '\r'
}

HSTS=$(extract_header "Strict-Transport-Security")
CSP=$(extract_header "Content-Security-Policy")
X_CONTENT_TYPE=$(extract_header "X-Content-Type-Options")
X_FRAME=$(extract_header "X-Frame-Options")
X_XSS=$(extract_header "X-XSS-Protection")
REFERRER=$(extract_header "Referrer-Policy")
PERMISSIONS=$(extract_header "Permissions-Policy")
SERVER=$(extract_header "Server")
CF_RAY=$(extract_header "CF-Ray")
CF_CACHE=$(extract_header "CF-Cache-Status")

# Check Critical Headers
echo -e "${CYAN}[2/5]${NC} Checking Critical Security Headers..."
echo ""

check_header "Strict-Transport-Security (HSTS)" "$HSTS" "true" "max-age=" "Enforces HTTPS connections"
check_header "Content-Security-Policy (CSP)" "$CSP" "true" "" "Prevents XSS and data injection"
check_header "X-Content-Type-Options" "$X_CONTENT_TYPE" "true" "nosniff" "Prevents MIME sniffing"
check_header "X-Frame-Options" "$X_FRAME" "true" "" "Prevents clickjacking"

echo ""

# Check Recommended Headers
echo -e "${CYAN}[3/5]${NC} Checking Recommended Headers..."
echo ""

check_header "X-XSS-Protection" "$X_XSS" "false" "1; mode=block" "Legacy XSS protection"
check_header "Referrer-Policy" "$REFERRER" "true" "" "Controls referrer information"
check_header "Permissions-Policy" "$PERMISSIONS" "false" "" "Feature policy controls"

echo ""

# Check Cloudflare Headers
echo -e "${CYAN}[4/5]${NC} Checking Cloudflare Configuration..."
echo ""

check_header "CF-Ray" "$CF_RAY" "true" "" "Cloudflare request ID"

if [ -n "$CF_RAY" ]; then
    echo -e "  ${GREEN}✓${NC} Cloudflare is active"
    echo -e "    ${CYAN}Ray ID:${NC} $CF_RAY"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    echo -e "  ${RED}✗${NC} Cloudflare not detected"
    echo -e "    ${YELLOW}→${NC} Site may not be protected by Cloudflare"
    FAILURES=$((FAILURES + 1))
fi
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

if [ -n "$CF_CACHE" ]; then
    echo -e "  ${BLUE}ℹ${NC}  Cache Status: $CF_CACHE"
fi

if [ -n "$SERVER" ]; then
    if [[ "$SERVER" == *"cloudflare"* ]]; then
        echo -e "  ${GREEN}✓${NC} Server header is proxied through Cloudflare"
    elif [[ "$SERVER" =~ (Apache|nginx|IIS) ]]; then
        echo -e "  ${YELLOW}⚠${NC} Server header exposes backend: $SERVER"
        echo -e "    ${YELLOW}→${NC} Consider obscuring server information"
        WARNINGS=$((WARNINGS + 1))
    fi
fi

echo ""

# Detailed Analysis
echo -e "${CYAN}[5/5]${NC} Security Analysis..."
echo ""

# HSTS Analysis
if [ -n "$HSTS" ]; then
    if [[ "$HSTS" =~ max-age=([0-9]+) ]]; then
        MAX_AGE=${BASH_REMATCH[1]}
        if [ "$MAX_AGE" -ge 31536000 ]; then
            echo -e "  ${GREEN}✓${NC} HSTS max-age is sufficient (${MAX_AGE}s = 1+ year)"
        else
            echo -e "  ${YELLOW}⚠${NC} HSTS max-age is too short (${MAX_AGE}s)"
            echo -e "    ${YELLOW}→${NC} Recommended: 31536000 (1 year)"
        fi
    fi

    if [[ "$HSTS" =~ includeSubDomains ]]; then
        echo -e "  ${GREEN}✓${NC} HSTS includes subdomains"
    else
        echo -e "  ${YELLOW}⚠${NC} HSTS does not include subdomains"
        echo -e "    ${YELLOW}→${NC} Consider adding 'includeSubDomains'"
    fi

    if [[ "$HSTS" =~ preload ]]; then
        echo -e "  ${GREEN}✓${NC} HSTS preload directive present"
    fi
fi

# CSP Analysis
if [ -n "$CSP" ]; then
    if [[ "$CSP" =~ default-src ]]; then
        echo -e "  ${GREEN}✓${NC} CSP has default-src directive"
    else
        echo -e "  ${YELLOW}⚠${NC} CSP missing default-src directive"
    fi

    if [[ "$CSP" =~ script-src ]]; then
        echo -e "  ${GREEN}✓${NC} CSP has script-src directive"
    fi

    if [[ "$CSP" =~ unsafe-inline ]]; then
        echo -e "  ${YELLOW}⚠${NC} CSP allows 'unsafe-inline'"
        echo -e "    ${YELLOW}→${NC} This weakens XSS protection"
    fi

    if [[ "$CSP" =~ unsafe-eval ]]; then
        echo -e "  ${YELLOW}⚠${NC} CSP allows 'unsafe-eval'"
        echo -e "    ${YELLOW}→${NC} This weakens XSS protection"
    fi
fi

# X-Frame-Options Analysis
if [ -n "$X_FRAME" ]; then
    if [[ "$X_FRAME" =~ DENY ]]; then
        echo -e "  ${GREEN}✓${NC} X-Frame-Options set to DENY (strongest)"
    elif [[ "$X_FRAME" =~ SAMEORIGIN ]]; then
        echo -e "  ${BLUE}ℹ${NC}  X-Frame-Options set to SAMEORIGIN (good)"
    else
        echo -e "  ${YELLOW}⚠${NC} X-Frame-Options value: $X_FRAME"
    fi
fi

echo ""

# Calculate Score
SCORE=0
if [ $TOTAL_CHECKS -gt 0 ]; then
    SCORE=$(echo "scale=1; ($PASSED_CHECKS * 100) / $TOTAL_CHECKS" | bc)
fi

# Summary
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                       ${MAGENTA}SUMMARY${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${BLUE}Total Checks:${NC} $TOTAL_CHECKS"
echo -e "${GREEN}Passed:${NC} $PASSED_CHECKS"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failures:${NC} $FAILURES"
echo ""

# Score display
if (( $(echo "$SCORE >= 90" | bc -l) )); then
    GRADE="${GREEN}A${NC}"
elif (( $(echo "$SCORE >= 80" | bc -l) )); then
    GRADE="${GREEN}B${NC}"
elif (( $(echo "$SCORE >= 70" | bc -l) )); then
    GRADE="${YELLOW}C${NC}"
elif (( $(echo "$SCORE >= 60" | bc -l) )); then
    GRADE="${YELLOW}D${NC}"
else
    GRADE="${RED}F${NC}"
fi

echo -e "${BLUE}Security Score:${NC} ${SCORE}% ${GRADE}"
echo ""

# Recommendations
if [ $FAILURES -gt 0 ] || [ $WARNINGS -gt 0 ]; then
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                   ${MAGENTA}RECOMMENDATIONS${NC}                       ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [ -z "$HSTS" ]; then
        echo -e "${YELLOW}→${NC} Add Strict-Transport-Security header:"
        echo -e "  ${CYAN}Strict-Transport-Security: max-age=31536000; includeSubDomains; preload${NC}"
        echo ""
    fi

    if [ -z "$CSP" ]; then
        echo -e "${YELLOW}→${NC} Add Content-Security-Policy header:"
        echo -e "  ${CYAN}Content-Security-Policy: default-src 'self'; script-src 'self'${NC}"
        echo ""
    fi

    if [ -z "$X_CONTENT_TYPE" ]; then
        echo -e "${YELLOW}→${NC} Add X-Content-Type-Options header:"
        echo -e "  ${CYAN}X-Content-Type-Options: nosniff${NC}"
        echo ""
    fi

    if [ -z "$X_FRAME" ]; then
        echo -e "${YELLOW}→${NC} Add X-Frame-Options header:"
        echo -e "  ${CYAN}X-Frame-Options: DENY${NC}"
        echo ""
    fi

    if [ -z "$REFERRER" ]; then
        echo -e "${YELLOW}→${NC} Add Referrer-Policy header:"
        echo -e "  ${CYAN}Referrer-Policy: strict-origin-when-cross-origin${NC}"
        echo ""
    fi

    if [ -z "$CF_RAY" ]; then
        echo -e "${YELLOW}→${NC} Site does not appear to be behind Cloudflare"
        echo -e "  Consider enabling Cloudflare for DDoS protection and WAF"
        echo ""
    fi
fi

# Cloudflare-specific recommendations
if [ -n "$CF_RAY" ]; then
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}              ${MAGENTA}CLOUDFLARE RECOMMENDATIONS${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Cloudflare Dashboard Settings:${NC}"
    echo ""
    echo -e "1. ${CYAN}SSL/TLS → Edge Certificates:${NC}"
    echo -e "   • Enable 'Always Use HTTPS'"
    echo -e "   • Enable 'HTTP Strict Transport Security (HSTS)'"
    echo -e "   • Set Minimum TLS Version to 1.2"
    echo ""
    echo -e "2. ${CYAN}Security → WAF:${NC}"
    echo -e "   • Enable OWASP ModSecurity Core Rule Set"
    echo -e "   • Review and enable relevant managed rulesets"
    echo ""
    echo -e "3. ${CYAN}Security → Settings:${NC}"
    echo -e "   • Set Security Level to 'High' or 'Medium'"
    echo -e "   • Enable 'Browser Integrity Check'"
    echo -e "   • Enable 'Challenge Passage'"
    echo ""
    echo -e "4. ${CYAN}Transform Rules:${NC}"
    echo -e "   • Add HTTP Response Header modifications"
    echo -e "   • Configure security headers via Transform Rules"
    echo ""
fi

# Final verdict
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [ $FAILURES -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}✅ EXCELLENT${NC} - All security headers properly configured!"
    else
        echo -e "${YELLOW}⚠️  GOOD${NC} - Core security headers present, but some improvements needed"
    fi
else
    echo -e "${RED}❌ NEEDS IMPROVEMENT${NC} - Critical security headers missing"
fi

echo ""

# Save to file if specified
if [ -n "$OUTPUT_FILE" ]; then
    {
        echo "Security Headers Report"
        echo "======================"
        echo "Target: $TARGET"
        echo "Date: $(date)"
        echo ""
        echo "Score: $SCORE%"
        echo "Passed: $PASSED_CHECKS/$TOTAL_CHECKS"
        echo "Warnings: $WARNINGS"
        echo "Failures: $FAILURES"
        echo ""
        echo "Headers:"
        echo "--------"
        echo "HSTS: $HSTS"
        echo "CSP: $CSP"
        echo "X-Content-Type-Options: $X_CONTENT_TYPE"
        echo "X-Frame-Options: $X_FRAME"
        echo "X-XSS-Protection: $X_XSS"
        echo "Referrer-Policy: $REFERRER"
        echo "Permissions-Policy: $PERMISSIONS"
        echo "CF-Ray: $CF_RAY"
        echo "Server: $SERVER"
    } > "$OUTPUT_FILE"
    echo -e "${GREEN}✓${NC} Report saved to: ${CYAN}$OUTPUT_FILE${NC}"
    echo ""
fi

# Exit with appropriate code
if [ $FAILURES -gt 0 ]; then
    exit 1
else
    exit 0
fi
