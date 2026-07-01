// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	manager "github.com/oakwood-commons/go-flight/cache"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// unimplementedServerMode provides default "not supported" responses for
// operations that are invalid in server mode. Embed this in concrete server
// mode implementations to inherit safe defaults for CLI-only methods.
type unimplementedServerMode struct{}

func (unimplementedServerMode) Login(context.Context, sdkplugin.LoginRequest, func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	return nil, fmt.Errorf("login is not supported in server mode")
}

func (unimplementedServerMode) Logout(context.Context) error {
	return fmt.Errorf("logout is not supported in server mode")
}

func (unimplementedServerMode) GetStatus(context.Context) (*auth.Status, error) {
	return nil, fmt.Errorf("get status is not supported in server mode")
}

func (unimplementedServerMode) ListCachedTokens(context.Context) ([]*auth.CachedTokenInfo, error) {
	return nil, fmt.Errorf("list cached tokens is not supported in server mode")
}

func (unimplementedServerMode) PurgeExpiredTokens(context.Context) (int, error) {
	return 0, fmt.Errorf("purge expired tokens is not supported in server mode")
}

func (unimplementedServerMode) DetectAvailableFlows(context.Context) ([]sdkplugin.FlowAvailability, error) {
	return nil, fmt.Errorf("detect available flows is not supported in server mode")
}

// entraServerMode implements mode for server-mode token acquisition.
// It is fully self-contained — holds its own tokenURL, clientID, tenantID,
// and credential rather than referencing the Plugin or CLI Config.
type entraServerMode struct {
	unimplementedServerMode
	tokenURL     string
	clientID     string
	tenantID     string
	credential   ServerCredential
	strategies   map[auth.ServerContext]FlowFn
	cacheManager *manager.Manager[string, *sdkplugin.TokenResponse]
	cleanup      func()
}

// Compile-time check that entraServerMode satisfies the mode interface.
var _ mode = (*entraServerMode)(nil)

func (s *entraServerMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	flow, ok := s.strategies[req.ServerContext]
	if !ok {
		return nil, fmt.Errorf("no strategy configured for context %q", req.ServerContext)
	}
	return flow(ctx, FlowParams{
		assertion: req.Assertion,
		Scope:     req.Scope,
		ClientID:  s.clientID,
		Caller:    req.Caller,
	})
}

// Stop signals the cleanup goroutine to exit. Safe to call multiple times.
func (s *entraServerMode) Stop() {
	if s.cleanup != nil {
		s.cleanup()
	}
}

// ServerModeOptions allows tests to override internal dependencies.
type ServerModeOptions struct {
	HTTPClient   HTTPClient
	CacheManager *manager.Manager[string, *sdkplugin.TokenResponse]
	CacheConfig  *CacheConfig
	Hooks        *manager.Hooks
}

// buildServerMode constructs a fully self-contained entraServerMode from the
// standalone ServerConfig. It does not reference the Plugin or CLI Config.
// opts may be nil for production defaults.
func buildServerMode(ctx context.Context, sc *ServerConfig, opts *ServerModeOptions) (*entraServerMode, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cred, err := resolveServerCredential(sc.ServerFlow, &sc.Credential)
	if err != nil {
		return nil, fmt.Errorf("resolving server credential: %w", err)
	}

	tokenURL := sc.TokenURL()
	strategies := make(map[auth.ServerContext]FlowFn)

	// Resolve HTTP client: injected (tests) or production server-mode client
	var httpClient HTTPClient
	if opts != nil && opts.HTTPClient != nil {
		httpClient = opts.HTTPClient
	} else {
		httpClient = newServerModeHTTPClient(lgr)
	}

	// Resolve cache manager: injected > built from config > built from defaults
	var mgr *manager.Manager[string, *sdkplugin.TokenResponse]
	var hooks *manager.Hooks
	var cleanup func()

	if opts != nil {
		mgr = opts.CacheManager
		hooks = opts.Hooks
	}
	if mgr == nil {
		cfg := DefaultCacheConfig()
		if opts != nil && opts.CacheConfig != nil {
			cfg = *opts.CacheConfig
		}
		stopCh := make(chan struct{})
		store := newLRUStoreAdapter(stopCh, cfg.StoreSize, cfg.StoreBuffer, cfg.CleanupInterval)
		mgr = newCacheManagerFromConfig(cfg, store)
		cleanup = sync.OnceFunc(func() { close(stopCh) })
	} else {
		cleanup = func() {}
	}

	// Server flow — always client_credentials grant
	strategies[auth.ServerContextServer] = cachedFlow(clientCredentialFlow(tokenURL, cred, httpClient), mgr, clientCredentialCacheKeyGenerator, nil, hooks)

	// Delegated flows — dispatches by CallerType internally
	if sc.Delegated != nil {
		var userFlow, machineFlow FlowFn

		// User delegation
		if sc.Delegated.UserFlow != "" {
			if sc.Delegated.UserFlow == auth.FlowOnBehalfOf {
				userFlow = cachedFlow(oboFlow(tokenURL, cred, httpClient), mgr, oboCacheKeyGenerator, nil, hooks)
			} else {
				// Must match server flow (validated earlier)
				userFlow = cachedFlow(clientCredentialFlow(tokenURL, cred, httpClient), mgr, clientCredentialCacheKeyGenerator, nil, hooks)
			}
		}

		// Machine delegation — always uses server flow (cached)
		if sc.Delegated.Machine {
			machineFlow = cachedFlow(clientCredentialFlow(tokenURL, cred, httpClient), mgr, clientCredentialCacheKeyGenerator, nil, hooks)
		}

		strategies[auth.ServerContextDelegated] = delegatedDispatch(userFlow, machineFlow)
	}

	return &entraServerMode{
		tokenURL:     tokenURL,
		clientID:     sc.ClientID,
		tenantID:     sc.TenantID,
		credential:   cred,
		strategies:   strategies,
		cacheManager: mgr,
		cleanup:      cleanup,
	}, nil
}
