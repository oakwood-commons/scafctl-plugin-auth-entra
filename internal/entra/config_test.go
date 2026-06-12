// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_MergeAdditionalScopes(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		input      []string
		want       []string
	}{
		{
			name:  "no additional scopes configured",
			cfg:   Config{},
			input: []string{"openid"},
			want:  []string{"openid"},
		},
		{
			name:  "merges without duplicates",
			cfg:   Config{AdditionalScopes: []string{"api://my-app/.default", "openid"}},
			input: []string{"openid", "profile"},
			want:  []string{"openid", "profile", "api://my-app/.default"},
		},
		{
			name:  "appends all when no overlap",
			cfg:   Config{AdditionalScopes: []string{"api://a/.default", "api://b/.default"}},
			input: []string{"openid"},
			want:  []string{"openid", "api://a/.default", "api://b/.default"},
		},
		{
			name:  "empty input scopes",
			cfg:   Config{AdditionalScopes: []string{"custom-scope"}},
			input: nil,
			want:  []string{"custom-scope"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.MergeAdditionalScopes(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConfig_ShouldInjectOIDCScopes(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name string
		cfg  Config
		want bool
	}{
		{
			name: "nil defaults to true",
			cfg:  Config{},
			want: true,
		},
		{
			name: "explicitly true",
			cfg:  Config{InjectOIDCScopes: boolPtr(true)},
			want: true,
		},
		{
			name: "explicitly false",
			cfg:  Config{InjectOIDCScopes: boolPtr(false)},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cfg.ShouldInjectOIDCScopes())
		})
	}
}
