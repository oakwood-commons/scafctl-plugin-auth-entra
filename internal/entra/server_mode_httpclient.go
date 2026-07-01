// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
)

// Server-mode HTTP client defaults.
const (
	serverHTTPTimeout             = 5 * time.Second
	serverHTTPRetryMax            = 2
	serverHTTPRetryWaitMin        = 200 * time.Millisecond
	serverHTTPRetryWaitMax        = 1 * time.Second
	serverHTTPDialTimeout         = 5 * time.Second
	serverHTTPKeepAlive           = 30 * time.Second
	serverHTTPMaxIdleConns        = 128
	serverHTTPMaxIdleConnsPerHost = 64
	serverHTTPIdleConnTimeout     = 60 * time.Second
	serverHTTPTLSHandshakeTimeout = 5 * time.Second
)

type serverModeHTTPClient struct {
	client *httpc.Client
}

func (c *serverModeHTTPClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.client.Do(req)
}

func newServerModeHTTPClient(logger logr.Logger) *serverModeHTTPClient {
	return &serverModeHTTPClient{
		client: httpc.NewClient(&httpc.ClientConfig{
			Timeout:           serverHTTPTimeout,
			RetryMax:          serverHTTPRetryMax,
			RetryWaitMin:      serverHTTPRetryWaitMin,
			RetryWaitMax:      serverHTTPRetryWaitMax,
			EnableCache:       false,
			EnableCompression: false,
			Logger:            logger,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   serverHTTPDialTimeout,
					KeepAlive: serverHTTPKeepAlive,
				}).DialContext,
				MaxIdleConns:        serverHTTPMaxIdleConns,
				MaxIdleConnsPerHost: serverHTTPMaxIdleConnsPerHost,
				IdleConnTimeout:     serverHTTPIdleConnTimeout,
				TLSHandshakeTimeout: serverHTTPTLSHandshakeTimeout,
				ForceAttemptHTTP2:   true,
			},
		}),
	}
}
