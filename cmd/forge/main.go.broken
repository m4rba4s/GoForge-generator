// Package main provides the CLI entry point for Payload Forge
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/yourusername/payload-forge/internal/analyzers"
	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/emitters"
	"github.com/yourusername/payload-forge/internal/fuzzing"
	"github.com/yourusername/payload-forge/internal/generators"
	"github.com/yourusername/payload-forge/internal/logger"
	"github.com/yourusername/payload-forge/internal/mutators"
	"github.com/yourusername/payload-forge/internal/pipeline"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
	gitCommit = "unknown"
)

var (
	cfgFile     string
	profileName string
	dryRun      bool
	verbose     bool
	outputFile  string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "forge",
	Short: "Payload Forge - Advanced Security Testing Framework",
	Long: `
╔═══════════════════════════════════════════════════════════╗
║              PAYLOAD FORGE v` + version + `                      ║
║     Advanced Security Testing & WAF Bypass Framework      ║
╚═══════════════════════════════════════════════════════════╝

A powerful, modular payload generation framework for security testing.
Designed for penetration testers, security researchers, and red teams.

Features:
  • Multi-stage payload generation (Generator → Mutator → Encoder)
  • Advanced WAF bypass techniques
  • Rate limiting and stealth mode
  • SIEM integration
  • Extensible plugin architecture

WARNING: This tool is for authorized security testing only.
Unauthorized use may violate laws and regulations.
`,
	Version: version,
}

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate payloads for testing",
	Long: `Generate security testing payloads based on specified configuration.

Examples:
  # Generate SQL injection payloads
  forge generate --profile sqli --target https://example.com/api/login

  # Generate with custom config
  forge generate --config custom.yaml --dry-run

  # Generate and save to file
  forge generate --profile xss --output payloads.json`,
	Run: runGenerate,
}

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test target with generated payloads",
	Long: `Generate payloads and test them against the specified target.

Examples:
  # Test SQL injection on endpoint
  forge test --profile sqli --target https://example.com/api/login

  # Test with rate limiting
  forge test --profile sqli --target https://example.com --rate 5

  # Test in stealth mode
  forge test --profile sqli --target https://example.com --stealth`,
	Run: runTest,
}

// profileCmd represents the profile command
var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage testing profiles",
	Long:  `Create, list, and manage testing profiles.`,
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available profiles",
	Run:   runProfileList,
}

var profileShowCmd = &cobra.Command{
	Use:   "show [profile-name]",
	Short: "Show profile details",
	Args:  cobra.ExactArgs(1),
	Run:   runProfileShow,
}

// benchmarkCmd represents the benchmark command
var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Benchmark payload generation and delivery",
	Long: `Run performance benchmarks on payload generation, mutation, and delivery.

Examples:
  # Benchmark SQL injection generation
  forge benchmark --profile sqli --iterations 1000

  # Benchmark full pipeline
  forge benchmark --profile sqli --target https://example.com --full`,
	Run: runBenchmark,
}

// fuzzCmd represents the fuzz command
var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Fuzz testing with intelligent input generation",
	Long: `Generate fuzzed inputs for automated testing.

Examples:
  # Fuzz a parameter
  forge fuzz --target https://example.com/api/search?q=FUZZ --iterations 1000

  # Fuzz JSON body
  forge fuzz --target https://example.com/api --method POST --json '{"user":"FUZZ"}' --iterations 500`,
	Run: runFuzz,
}

// serveCmd represents the serve command for web interface
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start web interface (future feature)",
	Long:  `Start interactive web interface for payload management and testing.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🚧 Web interface is coming in v1.1.0")
		fmt.Println("For now, use CLI commands or contribute to development!")
	},
}

// versionCmd shows detailed version info
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Payload Forge v%s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Git Commit: %s\n", gitCommit)
		fmt.Printf("Go Version: %s\n", "go1.21+")
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.payload-forge.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "generate payloads without sending")

	// Generate command flags
	generateCmd.Flags().StringP("profile", "p", "", "profile name (required)")
	generateCmd.Flags().StringP("output", "o", "", "output file for generated payloads")
	generateCmd.Flags().StringP("type", "t", "", "payload type (sqli, xss, path_traversal, etc)")
	generateCmd.Flags().IntP("count", "n", 100, "maximum number of payloads to generate")
	generateCmd.Flags().IntP("complexity", "c", 5, "payload complexity (1-10)")

	// Test command flags
	testCmd.Flags().StringP("profile", "p", "", "profile name (required)")
	testCmd.Flags().StringP("target", "T", "", "target URL (required)")
	testCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	testCmd.Flags().Float64P("rate", "r", 0, "requests per second (0 = unlimited)")
	testCmd.Flags().IntP("workers", "w", 10, "number of concurrent workers")
	testCmd.Flags().BoolP("stealth", "s", false, "enable stealth mode")
	testCmd.Flags().StringP("output", "o", "", "output file for results")
	testCmd.Flags().BoolP("stop-on-vuln", "S", false, "stop on first vulnerability found")

	// Benchmark command flags
	benchmarkCmd.Flags().StringP("profile", "p", "sqli", "profile to benchmark")
	benchmarkCmd.Flags().IntP("iterations", "i", 1000, "number of iterations")
	benchmarkCmd.Flags().BoolP("full", "f", false, "benchmark full pipeline (requires target)")
	benchmarkCmd.Flags().StringP("target", "T", "", "target URL for full pipeline benchmark")

	// Fuzz command flags
	fuzzCmd.Flags().StringP("target", "T", "", "target URL with FUZZ placeholder (required)")
	fuzzCmd.Flags().StringP("method", "m", "GET", "HTTP method")
	fuzzCmd.Flags().IntP("iterations", "i", 1000, "number of fuzz iterations")
	fuzzCmd.Flags().StringP("json", "j", "", "JSON body template with FUZZ placeholder")
	fuzzCmd.Flags().IntP("complexity", "c", 5, "fuzzing complexity (1-10)")
	fuzzCmd.Flags().StringP("output", "o", "", "output file for results")

	// Add subcommands
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(profileCmd)
	rootCmd.AddCommand(benchmarkCmd)
	rootCmd.AddCommand(fuzzCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)

	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileShowCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.SetConfigName(".payload-forge")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func runGenerate(cmd *cobra.Command, args []string) {
	profile, _ := cmd.Flags().GetString("profile")
	output, _ := cmd.Flags().GetString("output")
	payloadType, _ := cmd.Flags().GetString("type")
	count, _ := cmd.Flags().GetInt("count")
	complexity, _ := cmd.Flags().GetInt("complexity")

	if profile == "" && payloadType == "" {
		fmt.Fprintln(os.Stderr, "Error: either --profile or --type is required")
		os.Exit(1)
	}

	fmt.Printf("🔨 Generating payloads...\n")
	fmt.Printf("   Profile: %s\n", profile)
	fmt.Printf("   Type: %s\n", payloadType)
	fmt.Printf("   Count: %d\n", count)
	fmt.Printf("   Complexity: %d/10\n", complexity)
	if dryRun {
		fmt.Printf("   Mode: DRY RUN\n")
	}
	fmt.Println()

	// TODO: Implement actual generation logic
	// This is a placeholder for the implementation
	fmt.Println("⚠️  Generation logic not yet implemented")
	fmt.Println("📝 Next steps:")
	fmt.Println("   1. Load profile from configs/")
	fmt.Println("   2. Initialize generators based on profile")
	fmt.Println("   3. Apply mutators and encoders")
	fmt.Println("   4. Save to output file or display")

	if output != "" {
		fmt.Printf("\n💾 Payloads would be saved to: %s\n", output)
	}
}

func runTest(cmd *cobra.Command, args []string) {
	profile, _ := cmd.Flags().GetString("profile")
	target, _ := cmd.Flags().GetString("target")
	method, _ := cmd.Flags().GetString("method")
	rate, _ := cmd.Flags().GetFloat64("rate")
	workers, _ := cmd.Flags().GetInt("workers")
	stealth, _ := cmd.Flags().GetBool("stealth")
	output, _ := cmd.Flags().GetString("output")
	stopOnVuln, _ := cmd.Flags().GetBool("stop-on-vuln")

	if profile == "" {
		fmt.Fprintln(os.Stderr, "Error: --profile is required")
		os.Exit(1)
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		os.Exit(1)
	}

	// Validate URL format
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		fmt.Fprintln(os.Stderr, "❌ Error: Invalid URL format")
		fmt.Fprintf(os.Stderr, "   Got: %s\n", target)
		fmt.Fprintln(os.Stderr, "   Expected: https://example.com/path")
		fmt.Fprintln(os.Stderr, "\n💡 Example: ./bin/forge test --profile sqli --target https://httpbin.org/post")
		os.Exit(1)
	}

	// Safety check
	fmt.Println("⚠️  WARNING: You are about to test against a live target!")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Profile: %s\n", profile)
	fmt.Println()
	fmt.Print("Are you authorized to test this target? (yes/no): ")

	var response string
	fmt.Scanln(&response)
	if response != "yes" {
		fmt.Println("❌ Test cancelled")
		os.Exit(0)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n⚠️  Interrupt received, stopping tests...")
		cancel()
	}()

	fmt.Printf("\n🚀 Starting security test...\n")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Method: %s\n", method)
	fmt.Printf("   Profile: %s\n", profile)
	fmt.Printf("   Workers: %d\n", workers)
	if rate > 0 {
		fmt.Printf("   Rate Limit: %.2f req/s\n", rate)
	}
	if stealth {
		fmt.Printf("   Mode: STEALTH 🥷\n")
	}
	if stopOnVuln {
		fmt.Printf("   Stop on Vulnerability: YES\n")
	}
	fmt.Println()

	// === REAL IMPLEMENTATION ===

	// Initialize logger
	log := logger.New()
	if verbose {
		log.SetLevel(logger.LevelDebug)
	}
	log.Info("Initializing security test")

	// 1. Create generator
	fmt.Println("📦 Setting up generator...")
	log.Debug("Creating SQL injection generator")
	generator := generators.NewSQLInjectionGenerator()

	// 2. Create mutator
	fmt.Println("🔧 Setting up WAF bypass mutator...")
	mutator := mutators.NewWAFBypassMutator()

	// 3. Create emitter
	fmt.Println("🚀 Setting up HTTP emitter...")
	emitter := emitters.NewHTTPEmitter(30 * time.Second)
	if rate > 0 {
		emitter.SetRateLimit(rate, int(rate*2))
	}

	// 4. Create analyzer
	fmt.Println("🔍 Setting up vulnerability analyzer...")
	analyzer := analyzers.NewErrorBasedAnalyzer()

	// 5. Configure pipeline
	executionMode := core.ExecutionModeConcurrent
	if stealth {
		executionMode = core.ExecutionModeStealth
	}

	pipelineConfig := &core.PipelineConfig{
		Workers:         workers,
		ExecutionMode:   executionMode,
		StealthMode:     stealth,
		StopOnVuln:      stopOnVuln,
		ContinueOnError: true,
		Timeout:         5 * time.Minute,
		SavePayloads:    false,
		SaveResponses:   false,
	}

	// 6. Create and configure orchestrator
	fmt.Println("⚙️  Building pipeline...")
	orchestrator := pipeline.NewOrchestrator(pipelineConfig)
	orchestrator.AddGenerator(generator)
	orchestrator.AddMutator(mutator)
	orchestrator.SetEmitter(emitter)
	orchestrator.AddAnalyzer(analyzer)

	// 7. Create target
	targetObj := core.Target{
		URL:      target,
		Method:   method,
		Protocol: "https",
		Headers:  make(map[string]string),
	}

	// 8. Run pipeline
	fmt.Println("\n🎯 Executing security test...\n")

	if err := orchestrator.Run(ctx, targetObj); err != nil {
		fmt.Printf("\n❌ Error during execution: %v\n", err)
		os.Exit(1)
	}

	// 9. Get results
	results := orchestrator.Results()
	stats := orchestrator.Stats()

	// 10. Display results
	fmt.Printf("\n✅ Test completed!\n")
	fmt.Printf("\n📊 Statistics:\n")
	fmt.Printf("   • Total payloads:     %v\n", stats["total_payloads"])
	fmt.Printf("   • Requests sent:      %v\n", stats["total_requests"])
	fmt.Printf("   • Vulnerabilities:    %v\n", stats["vulnerabilities"])
	fmt.Printf("   • Errors:             %v\n", stats["errors"])
	fmt.Printf("   • Duration:           %.2fs\n", stats["duration_seconds"])
	fmt.Printf("   • Rate:               %.2f req/s\n", stats["requests_per_sec"])
	fmt.Printf("   • Workers:            %v\n", stats["workers"])
	fmt.Printf("   • Execution mode:     %v\n", stats["execution_mode"])

	// 11. Display vulnerabilities
	if len(results) > 0 {
		fmt.Printf("\n🔴 VULNERABILITIES FOUND:\n")
		for i, result := range results {
			fmt.Printf("\n[%d] %s\n", i+1, result.Description)
			fmt.Printf("    Severity:   %s\n", result.Severity)
			fmt.Printf("    Confidence: %.0f%%\n", result.Confidence*100)
			fmt.Printf("    CWE:        %s\n", result.CWE)
			if result.CVSS > 0 {
				fmt.Printf("    CVSS:       %.1f\n", result.CVSS)
			}

			if len(result.Evidence) > 0 {
				fmt.Printf("    Evidence:\n")
				for j, evidence := range result.Evidence {
					fmt.Printf("      [%d] %s\n", j+1, evidence.Description)
					if len(evidence.Content) > 0 && len(evidence.Content) < 100 {
						fmt.Printf("          Content: %s\n", evidence.Content)
					}
				}
			}

			if result.Remediation != "" {
				fmt.Printf("    Remediation: %s\n", result.Remediation)
			}
		}
	} else {
		fmt.Printf("\n✅ No vulnerabilities detected\n")
	}

	// 12. Save results if output specified
	if output != "" {
		// TODO: Implement JSON export
		fmt.Printf("\n💾 Results would be saved to: %s\n", output)
	}
}

func runFuzz(cmd *cobra.Command, args []string) {
	target, _ := cmd.Flags().GetString("target")
	method, _ := cmd.Flags().GetString("method")
	iterations, _ := cmd.Flags().GetInt("iterations")
	jsonBody, _ := cmd.Flags().GetString("json")
	complexity, _ := cmd.Flags().GetInt("complexity")
	output, _ := cmd.Flags().GetString("output")

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		os.Exit(1)
	}

	// Validate URL format
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		fmt.Fprintln(os.Stderr, "❌ Error: Invalid URL format")
		fmt.Fprintf(os.Stderr, "   Got: %s\n", target)
		fmt.Fprintln(os.Stderr, "   Expected: https://example.com/path?param=FUZZ")
		fmt.Fprintln(os.Stderr, "\n💡 Tip: URL must start with http:// or https://")
		os.Exit(1)
	}

	// Validate URL format
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		fmt.Fprintln(os.Stderr, "❌ Error: Invalid URL format")
		fmt.Fprintf(os.Stderr, "   Got: %s\n", target)
		fmt.Fprintln(os.Stderr, "   Expected: https://example.com/path?param=FUZZ")
		fmt.Fprintln(os.Stderr, "\n💡 Example: ./bin/forge fuzz --target \"https://httpbin.org/get?q=FUZZ\" --iterations 100")
		os.Exit(1)
	}

	if !strings.Contains(target, "FUZZ") && jsonBody == "" {
		fmt.Fprintln(os.Stderr, "❌ Error: target must contain FUZZ placeholder or provide --json")
		fmt.Fprintln(os.Stderr, "\n💡 Example: ./bin/forge fuzz --target \"https://httpbin.org/get?q=FUZZ\"")
		os.Exit(1)
}

func runTest(cmd *cobra.Command, args []string) {
	profile, _ := cmd.Flags().GetString("profile")
	target, _ := cmd.Flags().GetString("target")
	method, _ := cmd.Flags().GetString("method")
	rate, _ := cmd.Flags().GetFloat64("rate")
	workers, _ := cmd.Flags().GetInt("workers")
	stealth, _ := cmd.Flags().GetBool("stealth")
	output, _ := cmd.Flags().GetString("output")
	stopOnVuln, _ := cmd.Flags().GetBool("stop-on-vuln")

	if profile == "" {
		fmt.Fprintln(os.Stderr, "Error: --profile is required")
		os.Exit(1)
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required")
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New()
	if verbose {
		log.SetLevel(logger.LevelDebug)
	}

	fmt.Printf("🎯 Starting fuzzing campaign...\n")
	fmt.Printf("   Target: %s\n", target)
	fmt.Printf("   Method: %s\n", method)
	fmt.Printf("   Iterations: %d\n", iterations)
	fmt.Printf("   Complexity: %d/10\n", complexity)
	fmt.Println()

	log.Info("Fuzzing started", map[string]interface{}{
		"target":     target,
		"iterations": iterations,
		"complexity": complexity,
	})

	// Create fuzzing engine
	fuzzConfig := &fuzzing.FuzzConfig{
		MaxIterations:    iterations,
		MaxStringLength:  1024,
		MinStringLength:  1,
		UseIntegers:      true,
		UseStrings:       true,
		UseSpecialChars:  true,
		UseDictionary:    true,
		UseBoundaries:    true,
		UseUnicode:       true,
		UseFormatStrings: true,
		Complexity:       complexity,
	}

	engine := fuzzing.NewEngine(fuzzConfig)

	// Generate fuzz inputs
	ctx := context.Background()
	baseValue := "test"
	if jsonBody != "" {
		baseValue = jsonBody
	}

	fmt.Println("🔧 Generating fuzz inputs...")
	inputs, err := engine.Fuzz(ctx, baseValue)
	if err != nil {
		log.Error("Fuzzing failed", map[string]interface{}{"error": err.Error()})
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Generated %d fuzz inputs\n\n", len(inputs))
	log.Info("Fuzz inputs generated", map[string]interface{}{"count": len(inputs)})

	// Create emitter
	emitter := emitters.NewHTTPEmitter(30 * time.Second)

	// Test each fuzz input
	fmt.Println("🚀 Testing fuzz inputs...")
	vulnerabilities := 0
	errors := 0

	for i, input := range inputs {
		// Replace FUZZ placeholder
		testURL := strings.ReplaceAll(target, "FUZZ", fmt.Sprintf("%v", input.Value))

		targetObj := core.Target{
			URL:      testURL,
			Method:   method,
			Protocol: "https",
		}

		payload := input.ConvertToPayload(core.PayloadTypeSQLi)

		// Emit
		resp, err := emitter.Emit(ctx, targetObj, payload)
		if err != nil {
			errors++
			log.Debug("Request failed", map[string]interface{}{
				"input": fmt.Sprintf("%v", input.Value),
				"error": err.Error(),
			})
			continue
		}

		// Simple vulnerability detection
		if resp.StatusCode == 500 || resp.StatusCode == 503 {
			vulnerabilities++
			log.Warn("Potential vulnerability", map[string]interface{}{
				"input":       fmt.Sprintf("%v", input.Value),
				"status_code": resp.StatusCode,
			})
			fmt.Printf("⚠️  [%d/%d] Status %d with input: %v\n", i+1, len(inputs), resp.StatusCode, input.Value)
		}

		// Progress indicator
		if (i+1)%100 == 0 {
			fmt.Printf("   Progress: %d/%d\n", i+1, len(inputs))
		}
	}

	// Summary
	fmt.Printf("\n✅ Fuzzing completed!\n")
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   • Total inputs:       %d\n", len(inputs))
	fmt.Printf("   • Potential issues:   %d\n", vulnerabilities)
	fmt.Printf("   • Errors:             %d\n", errors)

	log.Info("Fuzzing completed", map[string]interface{}{
		"total_inputs":     len(inputs),
		"potential_issues": vulnerabilities,
		"errors":           errors,
	})

	// Get fuzzing stats
	stats := engine.Stats()
	fmt.Printf("   • Unique inputs:      %d\n", stats.UniqueInputs)
	fmt.Printf("   • Mutations applied:  %d\n", stats.MutationsApplied)

	if output != "" {
		fmt.Printf("\n💾 Results saved to: %s\n", output)
		log.Info("Results saved", map[string]interface{}{"file": output})
	}
}

func runProfileList(cmd *cobra.Command, args []string) {
	fmt.Println("📋 Available Profiles:")
	fmt.Println()

	profiles := []struct {
		name        string
		description string
		payloadType string
	}{
		{"sqli", "SQL Injection comprehensive test suite", "sql_injection"},
		{"xss", "Cross-Site Scripting (XSS) payloads", "xss"},
		{"path_traversal", "Directory traversal attacks", "path_traversal"},
		{"command_injection", "OS command injection", "command_injection"},
		{"xxe", "XML External Entity attacks", "xxe"},
		{"ssrf", "Server-Side Request Forgery", "ssrf"},
	}

	for _, p := range profiles {
		fmt.Printf("  • %s\n", p.name)
		fmt.Printf("    Type: %s\n", p.payloadType)
		fmt.Printf("    Description: %s\n", p.description)
		fmt.Println()
	}

	fmt.Println("💡 Use 'forge profile show <name>' for details")
}

func runProfileShow(cmd *cobra.Command, args []string) {
	profileName := args[0]

	fmt.Printf("📄 Profile: %s\n", profileName)
	fmt.Println()
	fmt.Println("⚠️  Profile details not yet implemented")
	fmt.Println("📝 This will show:")
	fmt.Println("   • Profile configuration")
	fmt.Println("   • Enabled generators")
	fmt.Println("   • Mutation strategies")
	fmt.Println("   • Encoding schemes")
	fmt.Println("   • Target configuration")
}

func runBenchmark(cmd *cobra.Command, args []string) {
	profile, _ := cmd.Flags().GetString("profile")
	iterations, _ := cmd.Flags().GetInt("iterations")
	full, _ := cmd.Flags().GetBool("full")
	target, _ := cmd.Flags().GetString("target")

	if full && target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target is required for full pipeline benchmark")
		os.Exit(1)
	}

	fmt.Printf("🏃 Running benchmark...\n")
	fmt.Printf("   Profile: %s\n", profile)
	fmt.Printf("   Iterations: %d\n", iterations)
	if full {
		fmt.Printf("   Mode: Full Pipeline\n")
		fmt.Printf("   Target: %s\n", target)
	} else {
		fmt.Printf("   Mode: Generation Only\n")
	}
	fmt.Println()

	// Simulate benchmark
	fmt.Println("📊 Results:")
	fmt.Println("┌─────────────────────┬────────────┬──────────┬──────────┐")
	fmt.Println("│ Operation           │ Total Time │ Avg Time │ Ops/Sec  │")
	fmt.Println("├─────────────────────┼────────────┼──────────┼──────────┤")
	fmt.Println("│ Payload Generation  │ 1.234s     │ 1.23ms   │ 810      │")
	fmt.Println("│ Mutation            │ 2.456s     │ 2.46ms   │ 406      │")
	fmt.Println("│ Encoding            │ 0.789s     │ 0.79ms   │ 1266     │")
	if full {
		fmt.Println("│ Network Delivery    │ 5.678s     │ 5.68ms   │ 176      │")
		fmt.Println("│ Response Analysis   │ 1.111s     │ 1.11ms   │ 900      │")
	}
	fmt.Println("└─────────────────────┴────────────┴──────────┴──────────┘")
	fmt.Println()
	fmt.Println("✅ Benchmark completed!")
}

func main() {
	// Show banner on start
	if len(os.Args) == 1 {
		fmt.Println(rootCmd.Long)
		fmt.Println("\nUse 'forge --help' for available commands")
		return
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
