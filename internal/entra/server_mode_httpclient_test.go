// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServerModeHTTPClient creates a server-mode client with AllowPrivateIPs
// enabled so httptest servers on localhost are reachable.
func newTestServerModeHTTPClient() *serverModeHTTPClient {
	return &serverModeHTTPClient{
		client: httpc.NewClient(&httpc.ClientConfig{
			Timeout:           serverHTTPTimeout,
			RetryMax:          serverHTTPRetryMax,
			RetryWaitMin:      serverHTTPRetryWaitMin,
			RetryWaitMax:      serverHTTPRetryWaitMax,
			EnableCache:       false,
			EnableCompression: false,
			Logger:            logr.Discard(),
			AllowPrivateIPs:   true,
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

func TestNewServerModeHTTPClient(t *testing.T) {
	client := newServerModeHTTPClient(logr.Discard())
	assert.NotNil(t, client)
	assert.NotNil(t, client.client)
}

func TestServerModeHTTPClient_PostForm_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		assert.Equal(t, "my-client", r.PostForm.Get("client_id"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	defer srv.Close()

	client := newTestServerModeHTTPClient()
	resp, err := client.PostForm(context.Background(), srv.URL, url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"my-client"},
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServerModeHTTPClient_ConnectionReuse(t *testing.T) {
	var connections atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	client := newTestServerModeHTTPClient()
	for i := 0; i < 10; i++ {
		resp, err := client.PostForm(context.Background(), srv.URL, url.Values{"grant_type": {"client_credentials"}})
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// All sequential requests should reuse a single connection
	assert.Equal(t, int32(1), connections.Load())
}
