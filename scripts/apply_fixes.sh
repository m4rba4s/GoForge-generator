#!/bin/bash
# apply_fixes.sh - Автоматическое применение критических фиксов
# Usage: ./scripts/apply_fixes.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PAYLOAD FORGE - AUTOMATED FIXES APPLICATION      ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}❌ Error: Must be run from payload-forge root directory${NC}"
    exit 1
fi

echo -e "${YELLOW}📋 Starting fixes application...${NC}"
echo ""

# Backup original files
echo -e "${BLUE}💾 Creating backups...${NC}"
mkdir -p .backups
cp internal/generators/sql_injection_test.go .backups/ 2>/dev/null || true
cp internal/mutators/waf_bypass.go .backups/ 2>/dev/null || true
cp internal/emitters/http.go .backups/ 2>/dev/null || true
echo -e "${GREEN}✅ Backups created in .backups/${NC}"
echo ""

# ============================================================================
# FIX #1: SQL Injection Test - Add BENCHMARK to time-based detection
# ============================================================================
echo -e "${YELLOW}🔧 Fix #1: SQL Injection Test (BENCHMARK detection)${NC}"

sed -i.bak '/case "time":/,/}/ {
    s/strings\.Contains(content, "DBMS_LOCK")/strings.Contains(content, "DBMS_LOCK") ||\n\t\t\t\tstrings.Contains(strings.ToUpper(content), "BENCHMARK")/
}' internal/generators/sql_injection_test.go

if grep -q "BENCHMARK" internal/generators/sql_injection_test.go; then
    echo -e "${GREEN}  ✓ Added BENCHMARK detection${NC}"
else
    echo -e "${RED}  ✗ Failed to add BENCHMARK detection - applying manual fix${NC}"
    # Manual patch as fallback
    cat > /tmp/fix1.patch << 'EOF'
--- a/internal/generators/sql_injection_test.go
+++ b/internal/generators/sql_injection_test.go
@@ -194,7 +194,8 @@ func TestSQLInjectionGenerate_AllTechniques(t *testing.T) {
 				case "time":
 					hasTime := strings.Contains(strings.ToUpper(content), "SLEEP") ||
 						strings.Contains(strings.ToUpper(content), "WAITFOR") ||
 						strings.Contains(content, "pg_sleep") ||
-						strings.Contains(content, "DBMS_LOCK")
+						strings.Contains(content, "DBMS_LOCK") ||
+						strings.Contains(strings.ToUpper(content), "BENCHMARK")
 					if !hasTime {
 						t.Errorf("Time-based payload doesn't contain time function: %s", content)
 					}
EOF
    patch -p1 < /tmp/fix1.patch || echo -e "${RED}Manual fix required for test file${NC}"
fi
echo ""

# ============================================================================
# FIX #2: WAF Bypass - Add input validation
# ============================================================================
echo -e "${YELLOW}🔧 Fix #2: WAF Bypass Mutator (empty payload validation)${NC}"

# Check if validation already exists
if grep -q "cannot mutate empty payload" internal/mutators/waf_bypass.go; then
    echo -e "${GREEN}  ✓ Validation already exists${NC}"
else
    # Add validation at the start of Mutate function
    sed -i.bak '/func (m \*WAFBypassMutator) Mutate/,/var mutations \[\]core.Payload/ {
        /var mutations \[\]core.Payload/i\
	// Validate input\
	if len(payload.Content) == 0 {\
		return nil, fmt.Errorf("cannot mutate empty payload")\
	}\

    }' internal/mutators/waf_bypass.go

    if grep -q "cannot mutate empty payload" internal/mutators/waf_bypass.go; then
        echo -e "${GREEN}  ✓ Added input validation${NC}"
    else
        echo -e "${RED}  ✗ Failed to add validation - manual fix required${NC}"
    fi
fi
echo ""

# ============================================================================
# FIX #3: HTTP Emitter - Add URL encoding for query parameters
# ============================================================================
echo -e "${YELLOW}🔧 Fix #3: HTTP Emitter (query parameter encoding)${NC}"

# Check if import alias exists
if grep -q 'neturl "net/url"' internal/emitters/http.go; then
    echo -e "${GREEN}  ✓ Import alias already exists${NC}"
else
    # Add import alias
    sed -i.bak 's|"net/http"|"net/http"\n\tneturl "net/url"|' internal/emitters/http.go

    if grep -q 'neturl "net/url"' internal/emitters/http.go; then
        echo -e "${GREEN}  ✓ Added import alias${NC}"
    else
        echo -e "${YELLOW}  ⚠ Import alias not added - may need manual fix${NC}"
    fi
fi

# Add QueryEscape for values
if grep -q "neturl.QueryEscape" internal/emitters/http.go; then
    echo -e "${GREEN}  ✓ Query encoding already exists${NC}"
else
    sed -i.bak '/value = strings.ReplaceAll(value, "{{payload}}", string(payload.Content))/a\
		encodedValue := neturl.QueryEscape(value)\
		url += fmt.Sprintf("%s%s=%s", separator, key, encodedValue)' internal/emitters/http.go

    # Remove old unencoded line
    sed -i.bak '/url += fmt.Sprintf("%s%s=%s", separator, key, value)/d' internal/emitters/http.go

    if grep -q "neturl.QueryEscape" internal/emitters/http.go; then
        echo -e "${GREEN}  ✓ Added query parameter encoding${NC}"
    else
        echo -e "${YELLOW}  ⚠ Encoding not added - may need manual fix${NC}"
    fi
fi
echo ""

# Clean up backup files
rm -f internal/generators/sql_injection_test.go.bak
rm -f internal/mutators/waf_bypass.go.bak
rm -f internal/emitters/http.go.bak

# ============================================================================
# Run Tests
# ============================================================================
echo -e "${BLUE}🧪 Running tests to verify fixes...${NC}"
echo ""

TEST_OUTPUT=$(mktemp)

# Test generators
echo -e "${YELLOW}Testing generators...${NC}"
if go test -v ./internal/generators/... 2>&1 | tee $TEST_OUTPUT | grep -q "FAIL"; then
    echo -e "${RED}  ✗ Generator tests still failing${NC}"
    grep "FAIL" $TEST_OUTPUT | head -5
    GENERATORS_OK=0
else
    echo -e "${GREEN}  ✓ All generator tests passing${NC}"
    GENERATORS_OK=1
fi
echo ""

# Test mutators
echo -e "${YELLOW}Testing mutators...${NC}"
if go test -v ./internal/mutators/... 2>&1 | tee $TEST_OUTPUT | grep -q "FAIL"; then
    echo -e "${RED}  ✗ Mutator tests still failing${NC}"
    grep "FAIL" $TEST_OUTPUT | head -5
    MUTATORS_OK=0
else
    echo -e "${GREEN}  ✓ All mutator tests passing${NC}"
    MUTATORS_OK=1
fi
echo ""

# Test emitters
echo -e "${YELLOW}Testing emitters...${NC}"
if go test -v ./internal/emitters/... 2>&1 | tee $TEST_OUTPUT | grep -q "FAIL"; then
    echo -e "${RED}  ✗ Emitter tests still failing${NC}"
    grep "FAIL" $TEST_OUTPUT | head -5
    EMITTERS_OK=0
else
    echo -e "${GREEN}  ✓ All emitter tests passing${NC}"
    EMITTERS_OK=1
fi
echo ""

rm -f $TEST_OUTPUT

# ============================================================================
# Summary
# ============================================================================
echo -e "${BLUE}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                   FIXES SUMMARY                       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_OK=$((GENERATORS_OK + MUTATORS_OK + EMITTERS_OK))

if [ $GENERATORS_OK -eq 1 ]; then
    echo -e "✅ ${GREEN}Generators:${NC} All tests passing"
else
    echo -e "❌ ${RED}Generators:${NC} Tests still failing"
fi

if [ $MUTATORS_OK -eq 1 ]; then
    echo -e "✅ ${GREEN}Mutators:${NC} All tests passing"
else
    echo -e "❌ ${RED}Mutators:${NC} Tests still failing"
fi

if [ $EMITTERS_OK -eq 1 ]; then
    echo -e "✅ ${GREEN}Emitters:${NC} All tests passing"
else
    echo -e "❌ ${RED}Emitters:${NC} Tests still failing"
fi

echo ""

if [ $TOTAL_OK -eq 3 ]; then
    echo -e "${GREEN}🎉 SUCCESS! All fixes applied successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Review changes with: git diff"
    echo "  2. Implement pipeline orchestrator"
    echo "  3. Add analyzers"
    echo "  4. Wire everything together in CLI"
    echo ""
    echo -e "${BLUE}📚 See FIXES_ROADMAP.md for detailed next steps${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  PARTIAL SUCCESS: $TOTAL_OK/3 components fixed${NC}"
    echo ""
    echo -e "${RED}Some fixes may require manual intervention.${NC}"
    echo "Check the output above for details."
    echo ""
    echo "Backups are available in .backups/ directory"
    echo ""
    echo -e "${YELLOW}To restore backups:${NC}"
    echo "  cp .backups/*.go internal/generators/"
    echo "  cp .backups/*.go internal/mutators/"
    echo "  cp .backups/*.go internal/emitters/"
    exit 1
fi
