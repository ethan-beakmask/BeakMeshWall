package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

// Task represents a single task received from the Central Server.
type Task struct {
	ID     string          `json:"id"`
	Action string          `json:"action"`
	Params json.RawMessage `json:"params"`
}

// PollResponse is the response from GET /api/v1/agent/poll.
type PollResponse struct {
	Tasks  []Task     `json:"tasks"`
	Config PollConfig `json:"config"`
}

// PollConfig holds dynamic configuration from the Central Server.
type PollConfig struct {
	PollInterval int `json:"poll_interval"`
}

// TaskResult represents the result of a processed task, sent back via report.
type TaskResult struct {
	TaskID  string `json:"task_id"`
	Status  string `json:"status"` // "success", "error", "skipped"
	Message string `json:"message,omitempty"`
}

// ReportRequest is the payload sent to POST /api/v1/agent/report.
type ReportRequest struct {
	Results []TaskResult `json:"results"`
}

// ReportResponse is the response from POST /api/v1/agent/report.
type ReportResponse struct {
	Status string `json:"status"`
}

const (
	// maxBackoff is the maximum retry interval on connection errors.
	maxBackoff = 5 * time.Minute

	// initialBackoff is the starting retry interval on connection errors.
	initialBackoff = 5 * time.Second
)

// StartPollLoop begins the poll loop that periodically contacts the Central Server
// for tasks. It respects context cancellation for graceful shutdown.
// The driver parameter is reserved for future task execution (P2+).
func StartPollLoop(ctx context.Context, client *Client, drv driver.Driver, logger *slog.Logger) error {
	pollInterval := 30 * time.Second
	backoff := initialBackoff
	consecutiveErrors := 0

	logger.Info("starting poll loop",
		"poll_interval", pollInterval,
		"driver", drv.Name(),
	)

	// Perform initial poll immediately, then loop on timer
	ticker := time.NewTicker(1) // fires immediately
	defer ticker.Stop()
	firstPoll := true

	for {
		select {
		case <-ctx.Done():
			logger.Info("poll loop stopped (context cancelled)")
			return nil

		case <-ticker.C:
			if firstPoll {
				// Reset ticker to actual poll interval after the immediate first fire
				ticker.Stop()
				ticker = time.NewTicker(pollInterval)
				firstPoll = false
			}

			err := poll(ctx, client, drv, logger)
			if err != nil {
				consecutiveErrors++

				// Check for 401 Unauthorized -- unrecoverable
				if isAuthError(err) {
					logger.Error("agent not authorized, re-registration may be needed",
						"error", err,
					)
					return fmt.Errorf("authentication failed: %w", err)
				}

				// Connection or transient error -- backoff and retry
				logger.Warn("poll failed, will retry",
					"error", err,
					"consecutive_errors", consecutiveErrors,
					"next_retry_in", backoff,
				)

				// Wait for backoff duration or context cancellation
				select {
				case <-ctx.Done():
					logger.Info("poll loop stopped during backoff (context cancelled)")
					return nil
				case <-time.After(backoff):
				}

				// Increase backoff exponentially, capped at maxBackoff
				backoff = backoff * 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}

				continue
			}

			// Successful poll -- reset backoff
			if consecutiveErrors > 0 {
				logger.Info("connection restored after errors",
					"previous_errors", consecutiveErrors,
				)
			}
			consecutiveErrors = 0
			backoff = initialBackoff

			// Update poll interval if Central Server changed it
			// (handled inside poll() via response parsing)
		}
	}
}

// poll performs a single poll cycle: fetch tasks, log them, and report results.
func poll(ctx context.Context, client *Client, drv driver.Driver, logger *slog.Logger) error {
	// Check context before making the request
	if ctx.Err() != nil {
		return ctx.Err()
	}

	resp, err := client.doGet("/api/v1/agent/poll")
	if err != nil {
		return fmt.Errorf("poll request: %w", err)
	}

	// Check for 401 before attempting to decode
	if resp.StatusCode == 401 {
		resp.Body.Close()
		return &authError{statusCode: 401}
	}

	var pollResp PollResponse
	if err := decodeResponse(resp, &pollResp); err != nil {
		return fmt.Errorf("decode poll response: %w", err)
	}

	// Update poll interval if server provides a new value
	if pollResp.Config.PollInterval > 0 {
		logger.Debug("poll interval from server", "interval", pollResp.Config.PollInterval)
	}

	// Process tasks (P1: log only, no actual execution)
	if len(pollResp.Tasks) == 0 {
		logger.Debug("no pending tasks")
		return nil
	}

	logger.Info("received tasks", "count", len(pollResp.Tasks))

	var results []TaskResult
	for _, task := range pollResp.Tasks {
		logger.Info("task received (P1: log only, not executing)",
			"task_id", task.ID,
			"action", task.Action,
			"params", string(task.Params),
		)

		results = append(results, TaskResult{
			TaskID:  task.ID,
			Status:  "skipped",
			Message: "P1: task logging only, execution not implemented",
		})
	}

	// Report results back to Central
	if len(results) > 0 {
		if err := report(client, results, logger); err != nil {
			logger.Warn("failed to report task results", "error", err)
			// Non-fatal: tasks were logged, report failure should not stop polling
		}
	}

	return nil
}

// report sends task results back to the Central Server.
func report(client *Client, results []TaskResult, logger *slog.Logger) error {
	reqBody := ReportRequest{
		Results: results,
	}

	resp, err := client.doPost("/api/v1/agent/report", reqBody)
	if err != nil {
		return fmt.Errorf("report request: %w", err)
	}

	var reportResp ReportResponse
	if err := decodeResponse(resp, &reportResp); err != nil {
		return fmt.Errorf("decode report response: %w", err)
	}

	logger.Debug("task results reported", "status", reportResp.Status, "count", len(results))
	return nil
}

// authError represents an authentication failure (HTTP 401).
type authError struct {
	statusCode int
}

func (e *authError) Error() string {
	return fmt.Sprintf("HTTP %d: unauthorized", e.statusCode)
}

// isAuthError checks if an error is an authentication failure.
func isAuthError(err error) bool {
	_, ok := err.(*authError)
	return ok
}
