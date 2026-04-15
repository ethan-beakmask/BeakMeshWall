package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client communicates with the Central Server.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) SetToken(token string) {
	c.token = token
}

// RegisterRequest is sent when agent first connects.
type RegisterRequest struct {
	Hostname     string `json:"hostname"`
	OSType       string `json:"os_type"`
	FWDriver     string `json:"fw_driver"`
	AgentVersion string `json:"agent_version"`
}

// RegisterResponse is returned after successful registration.
type RegisterResponse struct {
	NodeID       int    `json:"node_id"`
	Token        string `json:"token"`
	PollInterval int    `json:"poll_interval"`
}

// PollResponse contains tasks from Central.
type PollResponse struct {
	NodeID int          `json:"node_id"`
	Tasks  []TaskItem   `json:"tasks"`
}

type TaskItem struct {
	ID      int             `json:"id"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
}

// Register registers this agent with Central.
func (c *Client) Register(req RegisterRequest) (*RegisterResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.doRequest("POST", "/api/v1/agent/register", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register failed (HTTP %d): %s", resp.StatusCode, msg)
	}

	var result RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	return &result, nil
}

// Poll asks Central for pending tasks.
func (c *Client) Poll() (*PollResponse, error) {
	resp, err := c.doRequest("GET", "/api/v1/agent/poll", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("poll failed (HTTP %d): %s", resp.StatusCode, msg)
	}

	var result PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode poll response: %w", err)
	}
	return &result, nil
}

// Report sends firewall state and task results to Central.
func (c *Client) Report(data map[string]interface{}) error {
	body, _ := json.Marshal(data)
	resp, err := c.doRequest("POST", "/api/v1/agent/report", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed (HTTP %d): %s", resp.StatusCode, msg)
	}
	return nil
}

func (c *Client) doRequest(method, path string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return c.httpClient.Do(req)
}
