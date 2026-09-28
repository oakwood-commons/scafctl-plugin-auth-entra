// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"encoding/json"
	"testing"

	"github.com/oakwood-commons/httpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_GetAuthorityTrimsTrailingSlash(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		want      string
	}{
		{name: "no authority uses default", authority: "", want: DefaultAuthority},
		{name: "no trailing slash unchanged", authority: "https://login.microsoftonline.com", want: "https://login.microsoftonline.com"},
		{name: "single trailing slash trimmed", authority: "https://login.microsoftonline.com/", want: "https://login.microsoftonline.com"},
		{name: "multiple trailing slashes trimmed", authority: "https://login.microsoftonline.com//", want: "https://login.microsoftonline.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Authority: tc.authority}
			assert.Equal(t, tc.want, cfg.GetAuthority())
		})
	}
}

func TestConfig_HTTPClientParsing(t *testing.T) {
	t.Run("absent httpClient stays nil", func(t *testing.T) {
		var cfg Config
		require.NoError(t, json.Unmarshal([]byte(`{"clientId":"c","tenantId":"t"}`), &cfg))
		assert.Nil(t, cfg.HTTPClient)
	})

	t.Run("forwarded httpClient parsed", func(t *testing.T) {
		var cfg Config
		require.NoError(t, json.Unmarshal([]byte(`{
			"clientId":"c","tenantId":"t",
			"httpClient":{"timeout":"45s","retryMax":5,"retryWaitMin":"2s","retryWaitMax":"20s","enableCompression":true}
		}`), &cfg))
		require.NotNil(t, cfg.HTTPClient)
		assert.Equal(t, "45s", cfg.HTTPClient.Timeout)
		assert.Equal(t, 5, cfg.HTTPClient.RetryMax)
		assert.Equal(t, "2s", cfg.HTTPClient.RetryWaitMin)
		assert.Equal(t, "20s", cfg.HTTPClient.RetryWaitMax)
		require.NotNil(t, cfg.HTTPClient.EnableCompression)
		assert.True(t, *cfg.HTTPClient.EnableCompression)
	})
}

func TestMergeHTTPClientDefaults(t *testing.T) {
	t.Run("nil forwarded config keeps plugin defaults", func(t *testing.T) {
		merged := mergeHTTPClientDefaults(nil)
		assert.Equal(t, defaultHTTPTimeout.String(), merged.Timeout)
		assert.Equal(t, defaultHTTPRetryMax, merged.RetryMax)
		assert.Equal(t, defaultHTTPRetryWaitFloor.String(), merged.RetryWaitMin)
		assert.Equal(t, defaultHTTPRetryWaitMax.String(), merged.RetryWaitMax)
		require.NotNil(t, merged.EnableCache)
		assert.False(t, *merged.EnableCache)
		require.NotNil(t, merged.EnableCompression)
		assert.False(t, *merged.EnableCompression)
	})

	t.Run("forwarded values override defaults", func(t *testing.T) {
		merged := mergeHTTPClientDefaults(httpConfigForTest(t, `{"timeout":"5s","retryMax":1}`))
		assert.Equal(t, "5s", merged.Timeout)
		assert.Equal(t, 1, merged.RetryMax)
		// Unset fields keep the plugin defaults.
		assert.Equal(t, defaultHTTPRetryWaitMax.String(), merged.RetryWaitMax)
		require.NotNil(t, merged.EnableCache)
		assert.False(t, *merged.EnableCache)
	})

	t.Run("explicit cache and compression win", func(t *testing.T) {
		merged := mergeHTTPClientDefaults(httpConfigForTest(t, `{"enableCache":true,"enableCompression":true}`))
		require.NotNil(t, merged.EnableCache)
		assert.True(t, *merged.EnableCache)
		require.NotNil(t, merged.EnableCompression)
		assert.True(t, *merged.EnableCompression)
	})
}

// httpConfigForTest unmarshals a raw httpClient JSON object, failing the
// test on malformed input.
func httpConfigForTest(t *testing.T, raw string) *httpc.AppConfig {
	t.Helper()
	var cfg struct {
		HTTPClient *httpc.AppConfig `json:"httpClient"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"httpClient":`+raw+`}`), &cfg))
	require.NotNil(t, cfg.HTTPClient)
	return cfg.HTTPClient
}
