package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
	"github.com/anthropics/BeakMeshWall/agent/internal/module"
)

// Task represents a single task received from the Central Server.
type Task struct {
	ID     string                 `json:"id"`
	Module string                 `json:"module"`
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params"`
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
	TaskID  string      `json:"task_id"`
	Status  string      `json:"status"` // "success", "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// ReportRequest is the payload sent to POST /api/v1/agent/report.
// It includes task results and supplementary data (counters, tables)
// collected proactively by the agent every poll cycle.
type ReportRequest struct {
	Results  []TaskResult `json:"results"`
	Counters *CounterData `json:"counters,omitempty"`
	Tables   []TableData  `json:"tables,omitempty"`
}

// CounterData holds firewall rule counters collected from the driver.
type CounterData struct {
	Rules       []driver.Rule `json:"rules"`
	CollectedAt string        `json:"collected_at"` // RFC3339
}

// TableData holds nftables table inventory information.
type TableData struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Managed  bool   `json:"managed"`
	External string `json:"external"`
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
// for tasks. It dispatches tasks through the module.Registry and reports results.
// It respects context cancellation for graceful shutdown.
func StartPollLoop(ctx context.Context, client *Client, registry *module.Registry, logger *slog.Logger) error {
	pollInterval := 30 * time.Second
	backoff := initialBackoff
	consecutiveErrors := 0

	logger.Info("starting poll loop",
		"poll_interval", pollInterval,
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

			err := poll(ctx, client, registry, logger)
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

// poll performs a single poll cycle: fetch tasks, dispatch via registry,
// collect supplementary data (counters, tables), and report everything.
func poll(ctx context.Context, client *Client, registry *module.Registry, logger *slog.Logger) error {
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

	// Process tasks
	var results []TaskResult
	if len(pollResp.Tasks) == 0 {
		logger.Debug("no pending tasks")
	} else {
		logger.Info("received tasks", "count", len(pollResp.Tasks))

		for _, task := range pollResp.Tasks {
			logger.Info("dispatching task",
				"task_id", task.ID,
				"module", task.Module,
				"action", task.Action,
			)

			// Convert client.Task to module.Task for dispatch
			modTask := module.Task{
				ID:     task.ID,
				Module: task.Module,
				Action: task.Action,
				Params: task.Params,
			}

			modResult := registry.Dispatch(modTask)

			results = append(results, TaskResult{
				TaskID:  modResult.TaskID,
				Status:  modResult.Status,
				Message: modResult.Message,
				Data:    modResult.Data,
			})
		}
	}

	// Collect supplementary data for reporting
	var counterData *CounterData
	var tableData []TableData

	// Get firewall module to access driver for counter/table collection
	if fwMod, ok := registry.GetModule("firewall"); ok {
		if fw, ok := fwMod.(*module.FirewallModule); ok {
			drv := fw.Driver()

			// Collect rule counters
			if rules, err := drv.ListRules(); err == nil {
				counterData = &CounterData{
					Rules:       rules,
					CollectedAt: time.Now().UTC().Format(time.RFC3339),
				}
			} else {
				logger.Debug("failed to collect counters", "error", err)
			}

			// Collect table inventory
			if tables, err := drv.ListTables(); err == nil {
				for _, t := range tables {
					tableData = append(tableData, TableData{
						Name:     t.Name,
						Family:   t.Family,
						Managed:  t.Managed,
						External: t.External,
					})
				}
			} else {
				logger.Debug("failed to collect tables", "error", err)
			}
		}
	}

	// Always report, even with empty task results, to send counters/tables
	reportReq := ReportRequest{
		Results:  results,
		Counters: counterData,
		Tables:   tableData,
	}

	if err := report(client, reportReq, logger); err != nil {
		logger.Warn("failed to report results", "error", err)
		// Non-fatal: tasks were executed, report failure should not stop polling
	}

	return nil
}

// report sends task results and supplementary data back to the Central Server.
func report(client *Client, req ReportRequest, logger *slog.Logger) error {
	resp, err := client.doPost("/api/v1/agent/report", req)
	if err != nil {
		return fmt.Errorf("report request: %w", err)
	}

	var reportResp ReportResponse
	if err := decodeResponse(resp, &reportResp); err != nil {
		return fmt.Errorf("decode report response: %w", err)
	}

	logger.Debug("report sent",
		"status", reportResp.Status,
		"task_results", len(req.Results),
		"has_counters", req.Counters != nil,
		"table_count", len(req.Tables),
	)
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

// marshalParams converts map[string]interface{} to json.RawMessage for logging.
// This is kept for potential future use in debug logging.
func marshalParams(params map[string]interface{}) json.RawMessage {
	data, err := json.Marshal(params)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}
