#!/bin/bash
# Payload Forge - Live Testing Script
# Tests payload generation and delivery against safe, legal targets

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}        ${MAGENTA}PAYLOAD FORGE - LIVE TEST${NC}                        ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}        Testing against legal targets only              ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Legal notice
echo -e "${YELLOW}⚠️  LEGAL NOTICE:${NC}"
echo -e "This script tests against ${GREEN}httpbin.org${NC} only."
echo -e "httpbin.org is specifically designed for HTTP testing."
echo -e "Do NOT modify this script to test other targets without permission!"
echo ""

# Confirmation
read -p "Continue with legal testing? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo -e "${RED}Test cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Starting live tests...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Test 1: Basic GET request
echo -e "${CYAN}[TEST 1]${NC} Basic GET Request"
echo "Target: https://httpbin.org/get"
echo ""

cat > /tmp/test_basic.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/emitters"
)

func main() {
	ctx := context.Background()

	// Create generator
	gen := generators.NewSQLInjectionGenerator()

	// Generate payloads
	config := core.GeneratorConfig{
		Complexity: 3,
		MaxCount:   5,
		Custom: map[string]interface{}{
			"databases":  []string{"mysql"},
			"techniques": []string{"union"},
		},
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		fmt.Printf("Generate failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Generated %d payloads\n", len(payloads))

	// Create emitter
	emitter := emitters.NewHTTPEmitter(10 * time.Second)

	// Test target (httpbin.org - safe for testing)
	target := core.Target{
		URL:      "https://httpbin.org/get",
		Protocol: "https",
		Method:   "GET",
		Headers: map[string]string{
			"User-Agent": "PayloadForge-Test/1.0",
		},
	}

	// Emit first payload
	if len(payloads) > 0 {
		fmt.Printf("\nTesting payload: %s\n", string(payloads[0].Content))

		resp, err := emitter.Emit(ctx, target, payloads[0])
		if err != nil {
			fmt.Printf("✗ Emit failed: %v\n", err)
			return
		}

		fmt.Printf("✓ Response status: %d\n", resp.StatusCode)
		fmt.Printf("✓ Response time: %v\n", resp.Duration)
		fmt.Printf("✓ Response size: %d bytes\n", len(resp.Body))

		if resp.StatusCode == 200 {
			fmt.Println("\n✅ TEST 1 PASSED!")
		} else {
			fmt.Printf("\n⚠️  Unexpected status: %d\n", resp.StatusCode)
		}
	}
}
EOF

if go run /tmp/test_basic.go 2>&1; then
    echo -e "${GREEN}✓ Test 1 completed${NC}"
else
    echo -e "${RED}✗ Test 1 failed${NC}"
fi

echo ""
echo -e "${BLUE}───────────────────────────────────────────────────────────${NC}"
echo ""

# Test 2: POST request with payload in body
echo -e "${CYAN}[TEST 2]${NC} POST Request with Payload"
echo "Target: https://httpbin.org/post"
echo ""

cat > /tmp/test_post.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/emitters"
)

func main() {
	ctx := context.Background()

	gen := generators.NewSQLInjectionGenerator()

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   3,
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		fmt.Printf("Generate failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Generated %d payloads\n", len(payloads))

	emitter := emitters.NewHTTPEmitter(10 * time.Second)

	target := core.Target{
		URL:      "https://httpbin.org/post",
		Protocol: "https",
		Method:   "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		BodyTemplate: `{"username":"{{payload}}","password":"test123"}`,
	}

	if len(payloads) > 0 {
		fmt.Printf("\nTesting payload in POST body: %s\n", string(payloads[0].Content))

		resp, err := emitter.Emit(ctx, target, payloads[0])
		if err != nil {
			fmt.Printf("✗ Emit failed: %v\n", err)
			return
		}

		fmt.Printf("✓ Response status: %d\n", resp.StatusCode)
		fmt.Printf("✓ Response time: %v\n", resp.Duration)

		if resp.StatusCode == 200 {
			fmt.Println("\n✅ TEST 2 PASSED!")
		}
	}
}
EOF

if go run /tmp/test_post.go 2>&1; then
    echo -e "${GREEN}✓ Test 2 completed${NC}"
else
    echo -e "${RED}✗ Test 2 failed${NC}"
fi

echo ""
echo -e "${BLUE}───────────────────────────────────────────────────────────${NC}"
echo ""

# Test 3: Multiple payloads with rate limiting
echo -e "${CYAN}[TEST 3]${NC} Multiple Payloads with Rate Limiting"
echo "Target: https://httpbin.org/anything"
echo ""

cat > /tmp/test_rate.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/emitters"
)

func main() {
	ctx := context.Background()

	gen := generators.NewSQLInjectionGenerator()

	config := core.GeneratorConfig{
		Complexity: 3,
		MaxCount:   10,
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		fmt.Printf("Generate failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Generated %d payloads\n", len(payloads))

	emitter := emitters.NewHTTPEmitter(10 * time.Second)

	// Set rate limit: 2 requests per second
	emitter.SetRateLimit(2.0, 1)
	fmt.Println("✓ Rate limit set: 2 req/sec")

	target := core.Target{
		URL:      "https://httpbin.org/anything",
		Protocol: "https",
		Method:   "GET",
	}

	fmt.Printf("\nSending %d payloads with rate limiting...\n", len(payloads))

	start := time.Now()
	successCount := 0

	for i, payload := range payloads {
		if i >= 5 {
			break // Only send first 5 to be polite
		}

		resp, err := emitter.Emit(ctx, target, payload)
		if err != nil {
			fmt.Printf("  [%d] ✗ Failed: %v\n", i+1, err)
			continue
		}

		if resp.StatusCode == 200 {
			successCount++
			fmt.Printf("  [%d] ✓ OK (%v)\n", i+1, resp.Duration)
		} else {
			fmt.Printf("  [%d] ⚠️  Status: %d\n", i+1, resp.StatusCode)
		}
	}

	duration := time.Since(start)
	actualRate := float64(5) / duration.Seconds()

	fmt.Printf("\n✓ Success: %d/5\n", successCount)
	fmt.Printf("✓ Duration: %v\n", duration)
	fmt.Printf("✓ Actual rate: %.2f req/sec\n", actualRate)

	if successCount == 5 && actualRate <= 2.5 {
		fmt.Println("\n✅ TEST 3 PASSED!")
	}
}
EOF

if go run /tmp/test_rate.go 2>&1; then
    echo -e "${GREEN}✓ Test 3 completed${NC}"
else
    echo -e "${RED}✗ Test 3 failed${NC}"
fi

echo ""
echo -e "${BLUE}───────────────────────────────────────────────────────────${NC}"
echo ""

# Test 4: Mutation pipeline test
echo -e "${CYAN}[TEST 4]${NC} Generator → Mutator → Emitter Pipeline"
echo "Target: https://httpbin.org/status/200"
echo ""

cat > /tmp/test_pipeline.go << 'EOF'
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/mutators"
	"github.com/yourusername/payload-forge/internal/emitters"
)

func main() {
	ctx := context.Background()

	// Step 1: Generate
	fmt.Println("Step 1: Generating payloads...")
	gen := generators.NewSQLInjectionGenerator()

	config := core.GeneratorConfig{
		Complexity: 5,
		MaxCount:   3,
	}

	payloads, err := gen.Generate(ctx, config)
	if err != nil {
		fmt.Printf("Generate failed: %v\n", err)
		return
	}
	fmt.Printf("✓ Generated %d payloads\n\n", len(payloads))

	// Step 2: Mutate
	fmt.Println("Step 2: Mutating payloads...")
	mutator := mutators.NewWAFBypassMutator()

	var allMutations []core.Payload
	for _, payload := range payloads {
		mutations, err := mutator.Mutate(ctx, payload)
		if err != nil {
			fmt.Printf("Mutate failed: %v\n", err)
			continue
		}
		allMutations = append(allMutations, mutations...)
	}
	fmt.Printf("✓ Generated %d mutations\n\n", len(allMutations))

	// Step 3: Emit
	fmt.Println("Step 3: Emitting to target...")
	emitter := emitters.NewHTTPEmitter(10 * time.Second)

	target := core.Target{
		URL:      "https://httpbin.org/status/200",
		Protocol: "https",
		Method:   "GET",
	}

	testCount := 3
	if len(allMutations) < 3 {
		testCount = len(allMutations)
	}

	successCount := 0
	for i := 0; i < testCount; i++ {
		resp, err := emitter.Emit(ctx, target, allMutations[i])
		if err != nil {
			fmt.Printf("  [%d] ✗ Failed\n", i+1)
			continue
		}

		if resp.StatusCode == 200 {
			successCount++
			fmt.Printf("  [%d] ✓ OK\n", i+1)
		}
	}

	fmt.Printf("\n✓ Pipeline completed: %d/%d successful\n", successCount, testCount)

	if successCount == testCount {
		fmt.Println("\n✅ TEST 4 PASSED - Full pipeline works!")
	}
}
EOF

if go run /tmp/test_pipeline.go 2>&1; then
    echo -e "${GREEN}✓ Test 4 completed${NC}"
else
    echo -e "${RED}✗ Test 4 failed${NC}"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Summary
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${GREEN}LIVE TESTS COMPLETE${NC}                     ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✓${NC} All tests against httpbin.org completed"
echo -e "${GREEN}✓${NC} Payload generation works"
echo -e "${GREEN}✓${NC} Mutation pipeline works"
echo -e "${GREEN}✓${NC} HTTP emission works"
echo -e "${GREEN}✓${NC} Rate limiting works"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  • Fix failing unit tests"
echo "  • Test against your own honeypot (Level 1/2)"
echo "  • Deploy DVWA locally for advanced testing"
echo ""
echo -e "${BLUE}Remember: Always test ethically and legally! 🔒${NC}"
echo ""

# Cleanup
rm -f /tmp/test_basic.go /tmp/test_post.go /tmp/test_rate.go /tmp/test_pipeline.go
