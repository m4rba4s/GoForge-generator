// Package pipeline implements the payload testing pipeline orchestration
package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourusername/payload-forge/internal/core"
	"github.com/yourusername/payload-forge/internal/fuzzing"
	"github.com/yourusername/payload-forge/internal/logger"
)

// Orchestrator manages the entire testing pipeline
type Orchestrator struct {
	generators []core.Generator
	mutators   []core.Mutator
	encoders   []core.Encoder
	emitter    core.Emitter
	analyzers  []core.Analyzer

	config  *core.PipelineConfig
	results []core.Result
	mu      sync.RWMutex

	// Advanced features
	fuzzEngine *fuzzing.Engine
	logger     *logger.Logger

	// Metrics
	totalPayloads int64
	totalRequests int64
	totalVulns    int64
	totalErrors   int64
	startTime     time.Time

	// Control
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewOrchestrator creates a new pipeline orchestrator
func NewOrchestrator(config *core.PipelineConfig) *Orchestrator {
	if config == nil {
		config = &core.PipelineConfig{
			Workers:         10,
			ExecutionMode:   core.ExecutionModeConcurrent,
			StealthMode:     false,
			StopOnVuln:      false,
			ContinueOnError: true,
			Timeout:         5 * time.Minute,
			SavePayloads:    false,
			SaveResponses:   false,
		}
	}

	if config.Workers == 0 {
		config.Workers = 10
	}

	// Initialize fuzzing engine
	fuzzConfig := &fuzzing.FuzzConfig{
		MaxIterations:   config.Workers * 10,
		MaxStringLength: 1024,
		MinStringLength: 1,
		UseIntegers:     true,
		UseStrings:      true,
		UseSpecialChars: true,
		UseDictionary:   true,
		UseBoundaries:   true,
		Complexity:      5,
	}

	// Initialize logger
	log := logger.New()
	log.SetLevel(logger.LevelInfo)
	if config.DryRun {
		log.SetLevel(logger.LevelDebug)
	}

	return &Orchestrator{
		config:     config,
		results:    make([]core.Result, 0),
		startTime:  time.Now(),
		fuzzEngine: fuzzing.NewEngine(fuzzConfig),
		logger:     log,
	}
}

// AddGenerator adds a payload generator to the pipeline
func (o *Orchestrator) AddGenerator(gen core.Generator) {
	if gen != nil {
		o.generators = append(o.generators, gen)
	}
}

// AddMutator adds a payload mutator to the pipeline
func (o *Orchestrator) AddMutator(mut core.Mutator) {
	if mut != nil {
		o.mutators = append(o.mutators, mut)
	}
}

// AddEncoder adds an encoder to the pipeline
func (o *Orchestrator) AddEncoder(enc core.Encoder) {
	if enc != nil {
		o.encoders = append(o.encoders, enc)
	}
}

// SetEmitter sets the payload emitter
func (o *Orchestrator) SetEmitter(emit core.Emitter) {
	o.emitter = emit
}

// AddAnalyzer adds a response analyzer to the pipeline
func (o *Orchestrator) AddAnalyzer(analyzer core.Analyzer) {
	if analyzer != nil {
		o.analyzers = append(o.analyzers, analyzer)
	}
}

// Run executes the pipeline against the target
func (o *Orchestrator) Run(ctx context.Context, target core.Target) error {
	o.logger.Info("Starting pipeline execution", map[string]interface{}{
		"target": target.URL,
		"mode":   o.config.ExecutionMode,
	})

	// Validate configuration
	if err := o.validate(); err != nil {
		o.logger.Error("Validation failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("validation failed: %w", err)
	}

	// Create cancellable context
	pipelineCtx, cancel := context.WithTimeout(ctx, o.config.Timeout)
	o.cancel = cancel
	defer cancel()

	// Step 1: Generate base payloads
	o.logger.Info("Generating base payloads")
	basePayloads, err := o.generatePayloads(pipelineCtx)
	if err != nil {
		o.logger.Error("Payload generation failed", map[string]interface{}{"error": err.Error()})
		return fmt.Errorf("generate payloads: %w", err)
	}

	if len(basePayloads) == 0 {
		o.logger.Warn("No payloads generated")
		return fmt.Errorf("no payloads generated")
	}

	atomic.StoreInt64(&o.totalPayloads, int64(len(basePayloads)))
	o.logger.Info("Base payloads generated", map[string]interface{}{"count": len(basePayloads)})

	// Step 2: Apply mutations (if mutators configured)
	payloads := basePayloads
	if len(o.mutators) > 0 {
		o.logger.Info("Applying mutations", map[string]interface{}{"mutators": len(o.mutators)})
		payloads = o.applyMutations(pipelineCtx, basePayloads)
		o.logger.Info("Mutations applied", map[string]interface{}{"total_payloads": len(payloads)})
	}

	// Step 3: Apply encodings (if encoders configured)
	if len(o.encoders) > 0 {
		o.logger.Info("Applying encodings", map[string]interface{}{"encoders": len(o.encoders)})
		payloads = o.applyEncodings(pipelineCtx, payloads)
		o.logger.Info("Encodings applied", map[string]interface{}{"total_payloads": len(payloads)})
	}

	// Step 4: Execute based on mode
	o.logger.Info("Starting execution", map[string]interface{}{
		"mode":    o.config.ExecutionMode,
		"workers": o.config.Workers,
	})

	var execErr error
	switch o.config.ExecutionMode {
	case core.ExecutionModeSequential:
		execErr = o.executeSequential(pipelineCtx, target, payloads)
	case core.ExecutionModeConcurrent:
		execErr = o.executeConcurrent(pipelineCtx, target, payloads)
	case core.ExecutionModeAdaptive:
		execErr = o.executeAdaptive(pipelineCtx, target, payloads)
	case core.ExecutionModeStealth:
		execErr = o.executeStealth(pipelineCtx, target, payloads)
	default:
		execErr = o.executeConcurrent(pipelineCtx, target, payloads)
	}

	if execErr != nil {
		o.logger.Error("Execution failed", map[string]interface{}{"error": execErr.Error()})
	} else {
		o.logger.Info("Pipeline execution completed successfully")
	}

	return execErr
}

// validate checks if the pipeline is properly configured
func (o *Orchestrator) validate() error {
	if len(o.generators) == 0 {
		return fmt.Errorf("no generators configured")
	}

	if o.emitter == nil {
		return fmt.Errorf("no emitter configured")
	}

	if len(o.analyzers) == 0 {
		return fmt.Errorf("no analyzers configured")
	}

	return nil
}

// generatePayloads generates base payloads from all generators
func (o *Orchestrator) generatePayloads(ctx context.Context) ([]core.Payload, error) {
	var allPayloads []core.Payload

	for _, gen := range o.generators {
		select {
		case <-ctx.Done():
			return allPayloads, ctx.Err()
		default:
		}

		o.logger.Debug("Running generator", map[string]interface{}{"generator": gen.Name()})

		config := core.GeneratorConfig{
			Complexity: 5,
			MaxCount:   100,
			Custom:     make(map[string]interface{}),
		}

		payloads, err := gen.Generate(ctx, config)
		if err != nil {
			o.logger.Warn("Generator failed", map[string]interface{}{
				"generator": gen.Name(),
				"error":     err.Error(),
			})
			if o.config.ContinueOnError {
				atomic.AddInt64(&o.totalErrors, 1)
				continue
			}
			return nil, fmt.Errorf("generator %s failed: %w", gen.Name(), err)
		}

		o.logger.Debug("Generator produced payloads", map[string]interface{}{
			"generator": gen.Name(),
			"count":     len(payloads),
		})

		allPayloads = append(allPayloads, payloads...)
	}

	// Apply fuzzing to some base payloads (only if enabled)
	if len(allPayloads) > 0 && o.config.DryRun {
		// Fuzzing is optional and only for dry-run/testing
		o.logger.Debug("Applying fuzzing to base payloads")
		fuzzedPayloads := o.applyFuzzing(ctx, allPayloads[:min(5, len(allPayloads))])
		if len(fuzzedPayloads) > 0 {
			allPayloads = append(allPayloads, fuzzedPayloads...)
			o.logger.Debug("Fuzzing completed", map[string]interface{}{"fuzzed_count": len(fuzzedPayloads)})
		}
	}

	return allPayloads, nil
}

// applyMutations applies all mutators to payloads
func (o *Orchestrator) applyMutations(ctx context.Context, payloads []core.Payload) []core.Payload {
	if len(o.mutators) == 0 {
		return payloads
	}

	var mutated []core.Payload

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return mutated
		default:
		}

		// Keep original
		mutated = append(mutated, payload)

		// Apply each mutator
		for _, mut := range o.mutators {
			variants, err := mut.Mutate(ctx, payload)
			if err != nil {
				if o.config.ContinueOnError {
					atomic.AddInt64(&o.totalErrors, 1)
					continue
				}
				break
			}
			mutated = append(mutated, variants...)
		}
	}

	return mutated
}

// applyEncodings applies encoders to payloads
func (o *Orchestrator) applyEncodings(ctx context.Context, payloads []core.Payload) []core.Payload {
	if len(o.encoders) == 0 {
		return payloads
	}

	var encoded []core.Payload

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return encoded
		default:
		}

		// Keep original
		encoded = append(encoded, payload)

		// Apply encoders
		for _, enc := range o.encoders {
			encodedContent, err := enc.Encode(ctx, payload.Content)
			if err != nil {
				continue
			}

			encodedPayload := payload.Clone()
			encodedPayload.Content = encodedContent
			encodedPayload.Metadata["encoder"] = enc.Name()
			encoded = append(encoded, encodedPayload)
		}
	}

	return encoded
}

// executeSequential executes payloads one at a time
func (o *Orchestrator) executeSequential(ctx context.Context, target core.Target, payloads []core.Payload) error {
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := o.processPayload(ctx, target, payload, nil); err != nil {
			if !o.config.ContinueOnError {
				return err
			}
		}

		if o.config.StopOnVuln && atomic.LoadInt64(&o.totalVulns) > 0 {
			return nil
		}
	}

	return nil
}

// executeConcurrent executes payloads concurrently with worker pool
func (o *Orchestrator) executeConcurrent(ctx context.Context, target core.Target, payloads []core.Payload) error {
	// Create work channel
	work := make(chan core.Payload, len(payloads))
	errors := make(chan error, len(payloads))

	// Fill work channel
	for _, p := range payloads {
		work <- p
	}
	close(work)

	// Start workers
	for i := 0; i < o.config.Workers; i++ {
		o.wg.Add(1)
		go o.worker(ctx, target, work, errors, nil)
	}

	// Wait for completion
	go func() {
		o.wg.Wait()
		close(errors)
	}()

	// Collect errors
	var errs []error
	for err := range errors {
		if err != nil {
			errs = append(errs, err)
			if !o.config.ContinueOnError {
				o.Stop()
				break
			}
		}
	}

	if len(errs) > 0 && !o.config.ContinueOnError {
		return fmt.Errorf("encountered %d errors during execution", len(errs))
	}

	return nil
}

// executeAdaptive adjusts worker count based on response times
func (o *Orchestrator) executeAdaptive(ctx context.Context, target core.Target, payloads []core.Payload) error {
	// Start with half workers
	initialWorkers := o.config.Workers / 2
	if initialWorkers < 1 {
		initialWorkers = 1
	}

	work := make(chan core.Payload, len(payloads))
	errors := make(chan error, len(payloads))
	avgDuration := make(chan time.Duration, o.config.Workers)

	// Fill work channel
	for _, p := range payloads {
		work <- p
	}
	close(work)

	// Start initial workers
	for i := 0; i < initialWorkers; i++ {
		o.wg.Add(1)
		go o.worker(ctx, target, work, errors, avgDuration)
	}

	// Monitor and adjust workers (simplified version)
	go func() {
		for d := range avgDuration {
			if d < 100*time.Millisecond && len(work) > 0 {
				// Fast responses, add worker if under limit
				if initialWorkers < o.config.Workers {
					initialWorkers++
					o.wg.Add(1)
					go o.worker(ctx, target, work, errors, avgDuration)
				}
			}
		}
	}()

	o.wg.Wait()
	close(errors)
	close(avgDuration)

	// Collect errors
	var errs []error
	for err := range errors {
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 && !o.config.ContinueOnError {
		return fmt.Errorf("encountered %d errors", len(errs))
	}

	return nil
}

// executeStealth executes with delays and randomization for OPSEC
func (o *Orchestrator) executeStealth(ctx context.Context, target core.Target, payloads []core.Payload) error {
	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Random delay (30-120 seconds)
		delay := time.Duration(30+randInt(90)) * time.Second
		time.Sleep(delay)

		if err := o.processPayload(ctx, target, payload, nil); err != nil {
			if !o.config.ContinueOnError {
				return err
			}
		}

		if o.config.StopOnVuln && atomic.LoadInt64(&o.totalVulns) > 0 {
			return nil
		}
	}

	return nil
}

// worker processes payloads from work channel
func (o *Orchestrator) worker(ctx context.Context, target core.Target, work <-chan core.Payload, errors chan<- error, avgDuration chan<- time.Duration) {
	defer o.wg.Done()

	for payload := range work {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		err := o.processPayload(ctx, target, payload, avgDuration)
		duration := time.Since(start)

		if avgDuration != nil {
			select {
			case avgDuration <- duration:
			default:
			}
		}

		if err != nil {
			errors <- err
			if !o.config.ContinueOnError {
				return
			}
		}

		if o.config.StopOnVuln && atomic.LoadInt64(&o.totalVulns) > 0 {
			return
		}
	}
}

// processPayload sends payload and analyzes response
func (o *Orchestrator) processPayload(ctx context.Context, target core.Target, payload core.Payload, avgDuration chan<- time.Duration) error {
	o.logger.Debug("Processing payload", map[string]interface{}{"payload_id": payload.ID})

	// Emit payload
	resp, err := o.emitter.Emit(ctx, target, payload)
	if err != nil {
		o.logger.Debug("Failed to emit payload", map[string]interface{}{
			"payload_id": payload.ID,
			"error":      err.Error(),
		})
		// Don't count as error if it's a context cancellation
		if err != context.Canceled && err != context.DeadlineExceeded {
			atomic.AddInt64(&o.totalErrors, 1)
		}
		return fmt.Errorf("emit payload %s: %w", payload.ID, err)
	}

	atomic.AddInt64(&o.totalRequests, 1)

	o.logger.Debug("Payload emitted", map[string]interface{}{
		"payload_id":  payload.ID,
		"status_code": resp.StatusCode,
		"duration_ms": resp.Duration.Milliseconds(),
	})

	// Analyze response with all analyzers
	for _, analyzer := range o.analyzers {
		result, err := analyzer.Analyze(ctx, resp, nil, payload)
		if err != nil {
			o.logger.Debug("Analyzer failed", map[string]interface{}{
				"analyzer": analyzer.Name(),
				"error":    err.Error(),
			})
			continue
		}

		if result.Vulnerable {
			o.mu.Lock()
			o.results = append(o.results, *result)
			atomic.AddInt64(&o.totalVulns, 1)
			o.mu.Unlock()

			o.logger.Warn("Vulnerability detected!", map[string]interface{}{
				"payload_id": payload.ID,
				"severity":   result.Severity,
				"confidence": result.Confidence,
				"cwe":        result.CWE,
			})
		}
	}

	return nil
}

// Results returns all vulnerability findings
func (o *Orchestrator) Results() []core.Result {
	o.mu.RLock()
	defer o.mu.RUnlock()

	results := make([]core.Result, len(o.results))
	copy(results, o.results)
	return results
}

// Stop gracefully stops the pipeline
func (o *Orchestrator) Stop() {
	if o.cancel != nil {
		o.cancel()
	}
}

// Stats returns pipeline statistics
func (o *Orchestrator) Stats() map[string]interface{} {
	duration := time.Since(o.startTime)

	totalPayloads := atomic.LoadInt64(&o.totalPayloads)
	totalRequests := atomic.LoadInt64(&o.totalRequests)
	totalVulns := atomic.LoadInt64(&o.totalVulns)
	totalErrors := atomic.LoadInt64(&o.totalErrors)

	reqPerSec := 0.0
	if duration.Seconds() > 0 {
		reqPerSec = float64(totalRequests) / duration.Seconds()
	}

	return map[string]interface{}{
		"total_payloads":   totalPayloads,
		"total_requests":   totalRequests,
		"vulnerabilities":  totalVulns,
		"errors":           totalErrors,
		"duration_seconds": duration.Seconds(),
		"requests_per_sec": reqPerSec,
		"workers":          o.config.Workers,
		"execution_mode":   string(o.config.ExecutionMode),
	}
}

// randInt returns a random integer between 0 and n-1
func randInt(n int) int {
	// Simple pseudo-random for stealth delays
	return int(time.Now().UnixNano()%int64(n) + 1)
}

// applyFuzzing applies fuzzing to selected payloads
func (o *Orchestrator) applyFuzzing(ctx context.Context, payloads []core.Payload) []core.Payload {
	var fuzzed []core.Payload

	for _, payload := range payloads {
		select {
		case <-ctx.Done():
			return fuzzed
		default:
		}

		// Fuzz the payload content
		fuzzInputs, err := o.fuzzEngine.Fuzz(ctx, string(payload.Content))
		if err != nil {
			o.logger.Debug("Fuzzing failed", map[string]interface{}{"error": err.Error()})
			continue
		}

		// Convert fuzz inputs to payloads (limit to 5 per payload to avoid explosion)
		count := 0
		for _, fuzzInput := range fuzzInputs {
			if count >= 5 {
				break
			}
			// Skip empty or invalid inputs
			if fuzzInput.Value == nil || fmt.Sprintf("%v", fuzzInput.Value) == "" {
				continue
			}
			fuzzPayload := fuzzInput.ConvertToPayload(payload.Type)
			fuzzed = append(fuzzed, fuzzPayload)
			count++
		}
	}

	return fuzzed
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
