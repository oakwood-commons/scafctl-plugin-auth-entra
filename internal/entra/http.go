// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
)

// HTTPClient interface for token endpoint requests.
type HTTPClient interface {
	PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error)
}

// GraphClient handles authenticated GET requests to the Microsoft Graph API.
type GraphClient interface {
	Get(ctx context.Context, url, bearerToken string) (*http.Response, error)
}

// Default HTTP client settings.
const (
	defaultHTTPTimeout        = 30 * time.Second
	defaultHTTPRetryMax       = 3
	defaultHTTPRetryWaitFloor = 1 * time.Second
	defaultHTTPRetryWaitMax   = 10 * time.Second
)

// mergeHTTPClientDefaults returns the plugin's HTTP defaults as an
// httpc.AppConfig with the host-forwarded settings (auth.entra.httpClient)
// overlaid. Response caching and compression stay disabled for auth traffic
// unless the forwarded config explicitly enables them.
func mergeHTTPClientDefaults(cfg *httpc.AppConfig) *httpc.AppConfig {
	base := &httpc.AppConfig{
		Timeout:           defaultHTTPTimeout.String(),
		RetryMax:          defaultHTTPRetryMax,
		RetryWaitMin:      defaultHTTPRetryWaitFloor.String(),
		RetryWaitMax:      defaultHTTPRetryWaitMax.String(),
		EnableCache:       boolPtr(false),
		EnableCompression: boolPtr(false),
	}
	return httpc.MergeAppConfig(base, cfg)
}

func boolPtr(b bool) *bool { return &b }

// DefaultGraphClient implements GraphClient using httpc.
type DefaultGraphClient struct {
	client *httpc.Client
}

// NewDefaultGraphClient creates a new Graph API HTTP client. Forwarded
// auth.entra.httpClient settings overlay the plugin defaults; nil keeps them.
func NewDefaultGraphClient(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultGraphClient, error) {
	client, err := httpc.NewClientFromAppConfig(mergeHTTPClientDefaults(cfg), logger)
	if err != nil {
		return nil, err
	}
	return &DefaultGraphClient{client: client}, nil
}

// Get performs an authenticated GET request against the Microsoft Graph API.
func (c *DefaultGraphClient) Get(ctx context.Context, reqURL, bearerToken string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")
	return c.client.Do(req)
}

// DefaultHTTPClient implements HTTPClient using httpc.
type DefaultHTTPClient struct {
	client *httpc.Client
}

// NewDefaultHTTPClient creates a new default HTTP client backed by httpc.
// Forwarded auth.entra.httpClient settings overlay the plugin defaults; nil
// keeps them.
func NewDefaultHTTPClient(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultHTTPClient, error) {
	client, err := httpc.NewClientFromAppConfig(mergeHTTPClientDefaults(cfg), logger)
	if err != nil {
		return nil, err
	}
	return &DefaultHTTPClient{client: client}, nil
}

// PostForm performs a POST request with form-encoded data.
func (c *DefaultHTTPClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.client.Do(req)
}
