#!/bin/bash
# Payload Forge Test Runner
# Comprehensive test execution script with multiple test categories

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test categories
RUN_UNIT=false
RUN_SMOKE=false
RUN_SANITY=false
RUN_STRESS=false
RUN_INTEGRATION=false
RUN_ALL=false
VERBOSE=false
COVERAGE=false
RACE_DETECTOR=true

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Payload Forge Test Runner - Run different categories of tests

OPTIONS:
    -u, --unit          Run unit tests
    -s, --smoke         Run smoke tests (quick sanity checks)
    -n, --sanity        Run sanity tests (logic verification)
    -t, --stress        Run stress tests (performance & load)
    -i, --integration   Run integration tests
    -a, --all           Run all tests
    -c, --coverage      Generate coverage report
    -v, --verbose       Verbose output
    -r, --no-race       Disable race detector
    -h, --help          Show this help message

EXAMPLES:
    # Run unit tests only
    $0 --unit

    # Run smoke + sanity tests
    $0 --smoke --sanity

    # Run all tests with coverage
    $0 --all --coverage

    # Run stress tests with verbose output
    $0 --stress --verbose

EOF
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--unit)
            RUN_UNIT=true
            shift
            ;;
        -s|--smoke)
            RUN_SMOKE=true
            shift
            ;;
        -n|--sanity)
            RUN_SANITY=true
            shift
            ;;
        -t|--stress)
            RUN_STRESS=true
            shift
            ;;
        -i|--integration)
            RUN_INTEGRATION=true
            shift
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -r|--no-race)
            RACE_DETECTOR=false
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# If no test category specified, show usage
if ! $RUN_UNIT && ! $RUN_SMOKE && ! $RUN_SANITY && ! $RUN_STRESS && ! $RUN_INTEGRATION && ! $RUN_ALL; then
    echo -e "${RED}Error: No test category specified${NC}"
    echo ""
    usage
fi

# If --all is specified, enable all test categories
if $RUN_ALL; then
    RUN_UNIT=true
    RUN_SMOKE=true
    RUN_SANITY=true
    RUN_STRESS=true
    RUN_INTEGRATION=true
fi

# Build test flags
TEST_FLAGS=""
if $VERBOSE; then
    TEST_FLAGS="$TEST_FLAGS -v"
fi

if $RACE_DETECTOR; then
    TEST_FLAGS="$TEST_FLAGS -race"
fi

# Coverage flags
COVERAGE_FLAGS=""
COVERAGE_FILE="coverage.out"
if $COVERAGE; then
    COVERAGE_FLAGS="-coverprofile=$COVERAGE_FILE -covermode=atomic"
fi

# Function to print section header
print_header() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${MAGENTA}$1${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Function to print test result
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
    else
        echo -e "${RED}✗ FAILED${NC}"
    fi
}

# Track overall result
OVERALL_RESULT=0

# Start timestamp
START_TIME=$(date +%s)

print_header "🧪 PAYLOAD FORGE TEST SUITE"
echo -e "${BLUE}Test Configuration:${NC}"
echo -e "  Unit Tests:        $(if $RUN_UNIT; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Smoke Tests:       $(if $RUN_SMOKE; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Sanity Tests:      $(if $RUN_SANITY; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Stress Tests:      $(if $RUN_STRESS; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Integration Tests: $(if $RUN_INTEGRATION; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Coverage:          $(if $COVERAGE; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo -e "  Race Detector:     $(if $RACE_DETECTOR; then echo -e "${GREEN}enabled${NC}"; else echo -e "${YELLOW}disabled${NC}"; fi)"
echo ""

# Run Unit Tests
if $RUN_UNIT; then
    print_header "📦 UNIT TESTS"
    echo "Running unit tests for all internal packages..."
    echo ""

    if go test $TEST_FLAGS $COVERAGE_FLAGS -timeout 5m ./internal/...; then
        echo ""
        print_result 0
    else
        RESULT=$?
        echo ""
        print_result $RESULT
        OVERALL_RESULT=$RESULT
    fi
fi

# Run Smoke Tests
if $RUN_SMOKE; then
    print_header "🔥 SMOKE TESTS"
    echo "Running smoke tests (quick sanity checks)..."
    echo ""

    if go test $TEST_FLAGS -timeout 2m ./tests/smoke/...; then
        echo ""
        print_result 0
    else
        RESULT=$?
        echo ""
        print_result $RESULT
        OVERALL_RESULT=$RESULT
    fi
fi

# Run Sanity Tests
if $RUN_SANITY; then
    print_header "🧠 SANITY TESTS"
    echo "Running sanity tests (logic verification)..."
    echo ""

    # Sanity tests are the same as smoke tests in this implementation
    # But could be a separate category for more detailed logic checks
    if go test $TEST_FLAGS -timeout 3m ./tests/smoke/...; then
        echo ""
        print_result 0
    else
        RESULT=$?
        echo ""
        print_result $RESULT
        OVERALL_RESULT=$RESULT
    fi
fi

# Run Integration Tests
if $RUN_INTEGRATION; then
    print_header "🔗 INTEGRATION TESTS"
    echo "Running integration tests..."
    echo ""

    if go test $TEST_FLAGS -timeout 10m ./tests/integration/...; then
        echo ""
        print_result 0
    else
        RESULT=$?
        echo ""
        print_result $RESULT
        OVERALL_RESULT=$RESULT
    fi
fi

# Run Stress Tests
if $RUN_STRESS; then
    print_header "💪 STRESS TESTS"
    echo "Running stress tests (performance & load)..."
    echo "Note: This may take several minutes..."
    echo ""

    if go test $TEST_FLAGS -timeout 15m ./tests/stress/...; then
        echo ""
        print_result 0
    else
        RESULT=$?
        echo ""
        print_result $RESULT
        OVERALL_RESULT=$RESULT
    fi
fi

# Generate coverage report
if $COVERAGE; then
    print_header "📊 COVERAGE REPORT"

    if [ -f "$COVERAGE_FILE" ]; then
        echo "Generating coverage report..."
        go tool cover -func=$COVERAGE_FILE | tail -10
        echo ""

        # Generate HTML report
        HTML_COVERAGE="coverage.html"
        go tool cover -html=$COVERAGE_FILE -o $HTML_COVERAGE
        echo -e "${GREEN}✓${NC} HTML coverage report generated: ${BLUE}$HTML_COVERAGE${NC}"
        echo ""

        # Calculate total coverage
        TOTAL_COVERAGE=$(go tool cover -func=$COVERAGE_FILE | grep total | awk '{print $3}')
        echo -e "Total Coverage: ${MAGENTA}$TOTAL_COVERAGE${NC}"

        # Check if coverage meets threshold (85%)
        COVERAGE_NUM=$(echo $TOTAL_COVERAGE | sed 's/%//')
        if (( $(echo "$COVERAGE_NUM >= 85.0" | bc -l) )); then
            echo -e "${GREEN}✓ Coverage meets threshold (85%)${NC}"
        else
            echo -e "${YELLOW}⚠ Coverage below threshold: $TOTAL_COVERAGE < 85%${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ No coverage data generated${NC}"
    fi
fi

# Calculate execution time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Print summary
print_header "📋 TEST SUMMARY"

echo -e "Execution Time: ${CYAN}${DURATION}s${NC}"
echo ""

if [ $OVERALL_RESULT -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ALL TESTS PASSED ✓                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                    SOME TESTS FAILED ✗                     ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
    exit $OVERALL_RESULT
fi
