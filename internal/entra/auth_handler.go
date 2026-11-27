// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package entra implements the Microsoft Entra ID auth handler plugin.
package entra

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
)

const (
	// HandlerName is the unique identifier for this auth handler.
	HandlerName = "entra"

	// HandlerDisplayName is the human-readable name for the handler.
	HandlerDisplayName = "Microsoft Entra ID"

	// secretKeyBase is the base prefix for all Entra auth handler secrets.
	secretKeyBase = "scafctl.auth.entra" //nolint:gosec // key prefix, not a credential

	// secretSuffixRefreshToken is the key suffix for the refresh token.
	secretSuffixRefreshToken = "refresh_token" //nolint:gosec // key suffix, not a credential

	// secretSuffixMetadata is the key suffix for token metadata.
	secretSuffixMetadata = "metadata" //nolint:gosec // key suffix, not a credential

	// secretSuffixTokenPrefix is the key suffix for cached access tokens.
	secretSuffixTokenPrefix = "token." //nolint:gosec // key suffix, not a credential

	// SecretKeyRefreshToken is the default (no-profile) secret key for the refresh token.
	SecretKeyRefreshToken = secretKeyBase + "." + secretSuffixRefreshToken //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the default (no-profile) secret key for token metadata.
	SecretKeyMetadata = secretKeyBase + "." + secretSuffixMetadata //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the default (no-profile) prefix for cached access tokens.
	SecretKeyTokenPrefix = secretKeyBase + "." + secretSuffixTokenPrefix //nolint:gosec // key prefix, not a credential

	// DefaultTimeout is the default timeout for device code flow.
	DefaultTimeout = 5 * time.Minute

	// DefaultMinPollInterval is the minimum polling interval for device code flow.
	DefaultMinPollInterval = 5 * time.Second

	// DefaultRefreshTokenLifetime is the expected lifetime of refresh tokens.
	// Azure AD refresh tokens are valid for 90 days by default.
	DefaultRefreshTokenLifetime = 90 * 24 * time.Hour
)

// BrowserOpenFunc is the signature for a function that opens a URL in the browser.
type BrowserOpenFunc func(ctx context.Context, url string) error

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg               sdkplugin.ProviderConfig
	config            *Config
	httpClient        HTTPClient
	graphClient       GraphClient
	clock             clock.Clock
	cachedHostClient  *sdkplugin.HostServiceClient
	openBrowser       BrowserOpenFunc
	headlessReason    func() string
	mode              mode
	profileLocks      sync.Map
	cleanupTimeout    time.Duration
	orphanGracePeriod time.Duration
	nowFunc           func() time.Time

	clientCacheMu    sync.Mutex
	clientCacheSize  int
	baseLogger       logr.Logger
	initHTTPKey      effectiveHTTPConfigKey
	hasInitHTTPKey   bool
	initHTTPHandle   *clientRefHandle
	initGraphHandle  *clientRefHandle
	httpClientCache  *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient]
	graphClientCache *boundedClientCache[effectiveHTTPConfigKey, *DefaultGraphClient]
}

// profileRWMutex is a context-aware, writer-preferring reader/writer lock.
// Waiting Lock and RLock callers return ctx.Err() immediately when ctx is
// canceled while another caller holds the lock across host secret-store I/O.
type profileRWMutex struct {
	mu             sync.Mutex
	writerActive   bool
	writersWaiting int
	readersActive  int
	notify         chan struct{}
}

func newProfileRWMutex() *profileRWMutex {
	return &profileRWMutex{notify: make(chan struct{})}
}

func (m *profileRWMutex) broadcastLocked() {
	close(m.notify)
	m.notify = make(chan struct{})
}

func (m *profileRWMutex) Lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if !m.writerActive && m.readersActive == 0 {
		m.writerActive = true
		m.mu.Unlock()
		return nil
	}
	m.writersWaiting++
	for {
		ch := m.notify
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.writersWaiting--
			if m.writersWaiting == 0 && !m.writerActive {
				m.broadcastLocked()
			}
			m.mu.Unlock()
			return ctx.Err()
		case <-ch:
			if err := ctx.Err(); err != nil {
				m.mu.Lock()
				m.writersWaiting--
				if m.writersWaiting == 0 && !m.writerActive {
					m.broadcastLocked()
				}
				m.mu.Unlock()
				return err
			}
			m.mu.Lock()
			if !m.writerActive && m.readersActive == 0 {
				m.writersWaiting--
				m.writerActive = true
				m.mu.Unlock()
				return nil
			}
		}
	}
}

func (m *profileRWMutex) Unlock() {
	m.mu.Lock()
	if !m.writerActive {
		m.mu.Unlock()
		panic("entra: Unlock of unlocked profileRWMutex")
	}
	m.writerActive = false
	m.broadcastLocked()
	m.mu.Unlock()
}

func (m *profileRWMutex) RLock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if !m.writerActive && m.writersWaiting == 0 {
		m.readersActive++
		m.mu.Unlock()
		return nil
	}
	for {
		ch := m.notify
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			if err := ctx.Err(); err != nil {
				return err
			}
			m.mu.Lock()
			if !m.writerActive && m.writersWaiting == 0 {
				m.readersActive++
				m.mu.Unlock()
				return nil
			}
		}
	}
}

func (m *profileRWMutex) RUnlock() {
	m.mu.Lock()
	if m.readersActive <= 0 {
		m.mu.Unlock()
		panic("entra: RUnlock of unlocked profileRWMutex")
	}
	m.readersActive--
	if m.readersActive == 0 {
		m.broadcastLocked()
	}
	m.mu.Unlock()
}

func isContextErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		switch status.Code(e) { //nolint:exhaustive // only context-cancellation gRPC codes are checked
		case codes.Canceled, codes.DeadlineExceeded:
			return true
		}
	}
	return false
}

// contextErr returns a context error when err is itself a cancellation/deadline
// error or when err failed after ctx was already canceled (for example, when
// the host serializes a canceled SecretStore operation into a plain string
// response error without gRPC status codes).
func contextErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if isContextErr(err) {
		return err
	}
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// profileLock returns the profile-scoped context-aware RWMutex coordinating
// in-process credential snapshots, writes, rollbacks, logouts, and session reads.
func (p *Plugin) profileLock(ctx context.Context) *profileRWMutex {
	profile := auth.ProfileFromContext(ctx)
	if v, ok := p.profileLocks.Load(profile); ok {
		return v.(*profileRWMutex)
	}
	mu := newProfileRWMutex()
	actual, _ := p.profileLocks.LoadOrStore(profile, mu)
	return actual.(*profileRWMutex)
}

var (
	_ sdkplugin.AuthHandlerPlugin  = (*Plugin)(nil)
	_ sdkplugin.ServerMode         = (*Plugin)(nil)
	_ sdkplugin.AuthGroupsProvider = (*Plugin)(nil)
)

type resolvedConfigKeyType struct{}

func withResolvedConfig(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, resolvedConfigKeyType{}, cfg)
}

func resolvedConfigFromContext(ctx context.Context) (*Config, bool) {
	cfg, ok := ctx.Value(resolvedConfigKeyType{}).(*Config)
	return cfg, ok && cfg != nil
}

func attachRequestSettings(ctx context.Context, reqSettings map[string]json.RawMessage) context.Context {
	if _, ok := sdkplugin.RequestSettingsFromContext(ctx); !ok && reqSettings != nil {
		return sdkplugin.WithRequestSettings(ctx, reqSettings)
	}
	return ctx
}

func parseHandlerConfig(raw []byte) (*Config, error) {
	cfg := DefaultConfig()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse handler config: %w", err)
		}
	}

	// Restore defaults for fields that were not explicitly set (or were set
	// to empty) so that Validate succeeds, whether the config came from a
	// profile or top-level settings. The actual env var fallback happens
	// later in profileOrEnv during resolve calls.
	if !cfg.WasSet("clientId") && cfg.ClientID == "" {
		cfg.ClientID = DefaultClientID
	}
	if !cfg.WasSet("tenantId") && cfg.TenantID == "" {
		cfg.TenantID = DefaultTenantID
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// effectiveConfig returns the handler Config to use for ctx: per-RPC request
// settings from RequestSettingsFromContext(ctx) when present, falling back to
// the ConfigureAuthHandler config without mutating p.config.
func (p *Plugin) effectiveConfig(ctx context.Context) (*Config, error) {
	if cfg, ok := resolvedConfigFromContext(ctx); ok {
		return cfg, nil
	}
	if settings, ok := sdkplugin.RequestSettingsFromContext(ctx); ok {
		var raw []byte
		if nested, hasHandler := settings[HandlerName]; hasHandler {
			if !bytes.Equal(bytes.TrimSpace(nested), []byte("null")) {
				raw = nested
			}
		} else if len(settings) > 0 {
			var err error
			raw, err = json.Marshal(settings)
			if err != nil {
				return nil, fmt.Errorf("failed to encode request settings: %w", err)
			}
		}

		reqCfg, err := parseHandlerConfig(raw)
		if err != nil {
			return nil, err
		}
		if p.config != nil {
			reqCfg.MinPollInterval = p.config.MinPollInterval
			reqCfg.SlowDownIncrement = p.config.SlowDownIncrement
		}
		return reqCfg, nil
	}
	if p.config != nil {
		return p.config, nil
	}
	return DefaultConfig(), nil
}

func pickHTTPLogger(ctx context.Context, baseLogger logr.Logger) logr.Logger {
	if baseLogger.GetSink() != nil {
		return baseLogger.V(5)
	}
	return logr.FromContextOrDiscard(ctx).V(5)
}

func (p *Plugin) ensureHTTPClientCacheLocked() *boundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient] {
	if p.httpClientCache == nil {
		p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	}
	return p.httpClientCache
}

func (p *Plugin) ensureGraphClientCacheLocked() *boundedClientCache[effectiveHTTPConfigKey, *DefaultGraphClient] {
	if p.graphClientCache == nil {
		p.graphClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultGraphClient](p.clientCacheSize)
	}
	return p.graphClientCache
}

func (p *Plugin) httpClientForConfig(ctx context.Context, cfg *Config) (HTTPClient, func(), error) {
	var appCfg *httpc.AppConfig
	if cfg != nil {
		appCfg = cfg.HTTPClient
	}

	key, clientCfg, err := resolveEffectiveHTTPConfig(appCfg)
	if err != nil {
		return nil, noopRelease, fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	p.clientCacheMu.Lock()
	curHTTP := p.httpClient
	hasInit := p.hasInitHTTPKey
	initKey := p.initHTTPKey
	baseLgr := p.baseLogger
	if curHTTP != nil {
		defHTTP, isDefault := curHTTP.(*DefaultHTTPClient)
		if !isDefault {
			p.clientCacheMu.Unlock()
			return curHTTP, noopRelease, nil
		}
		if hasInit && key == initKey {
			if p.initHTTPHandle != nil && p.initHTTPHandle.closer == defHTTP {
				if rel, ok := p.initHTTPHandle.tryAcquire(); ok {
					p.clientCacheMu.Unlock()
					return curHTTP, rel, nil
				}
			} else if p.initHTTPHandle != nil {
				p.clientCacheMu.Unlock()
				return curHTTP, noopRelease, nil
			}
		}
	} else if cfg == nil || (p.config != nil && cfg == p.config) {
		p.clientCacheMu.Unlock()
		return nil, noopRelease, fmt.Errorf("HTTP client not initialized")
	}
	cache := p.ensureHTTPClientCacheLocked()
	p.clientCacheMu.Unlock()

	client, rel := cache.Acquire(key, func() *DefaultHTTPClient {
		return newDefaultHTTPClientFromResolved(clientCfg, pickHTTPLogger(ctx, baseLgr))
	})
	return client, rel, nil
}

func (p *Plugin) graphClientForConfig(ctx context.Context, cfg *Config) (GraphClient, func(), error) {
	var appCfg *httpc.AppConfig
	if cfg != nil {
		appCfg = cfg.HTTPClient
	}

	key, clientCfg, err := resolveEffectiveHTTPConfig(appCfg)
	if err != nil {
		return nil, noopRelease, fmt.Errorf("failed to build Graph client from httpClient config: %w", err)
	}
	graphKey := key.withoutHTTPCache()

	p.clientCacheMu.Lock()
	curGraph := p.graphClient
	hasInit := p.hasInitHTTPKey
	initKey := p.initHTTPKey.withoutHTTPCache()
	baseLgr := p.baseLogger
	if curGraph != nil {
		defGraph, isDefault := curGraph.(*DefaultGraphClient)
		if !isDefault {
			p.clientCacheMu.Unlock()
			return curGraph, noopRelease, nil
		}
		if hasInit && graphKey == initKey {
			if p.initGraphHandle != nil && p.initGraphHandle.closer == defGraph {
				if rel, ok := p.initGraphHandle.tryAcquire(); ok {
					p.clientCacheMu.Unlock()
					return curGraph, rel, nil
				}
			} else if p.initGraphHandle != nil {
				p.clientCacheMu.Unlock()
				return curGraph, noopRelease, nil
			}
		}
	} else if cfg == nil || (p.config != nil && cfg == p.config) {
		p.clientCacheMu.Unlock()
		return nil, noopRelease, fmt.Errorf("graph client not initialized")
	}
	cache := p.ensureGraphClientCacheLocked()
	p.clientCacheMu.Unlock()

	client, rel := cache.Acquire(graphKey, func() *DefaultGraphClient {
		return newDefaultGraphClientFromResolved(clientCfg, pickHTTPLogger(ctx, baseLgr))
	})
	return client, rel, nil
}

func (p *Plugin) closeHTTPClients() {
	p.clientCacheMu.Lock()
	httpCache := p.ensureHTTPClientCacheLocked()
	graphCache := p.ensureGraphClientCacheLocked()
	curHTTP := p.httpClient
	curGraph := p.graphClient
	httpHandle := p.initHTTPHandle
	graphHandle := p.initGraphHandle
	p.clientCacheMu.Unlock()

	httpCache.CloseAll()
	graphCache.CloseAll()
	if defHTTP, ok := curHTTP.(*DefaultHTTPClient); ok {
		if httpHandle != nil && httpHandle.closer == defHTTP {
			httpHandle.retire()
		} else {
			_ = defHTTP.Close()
		}
	}
	if defGraph, ok := curGraph.(*DefaultGraphClient); ok {
		if graphHandle != nil && graphHandle.closer == defGraph {
			graphHandle.retire()
		} else {
			_ = defGraph.Close()
		}
	}
}

// activeMode returns the current mode. This guard returns an explicit error
// rather than panicking if the invariant is violated.
func (p *Plugin) activeMode() (mode, error) {
	if p.mode == nil {
		return nil, fmt.Errorf("auth handler not configured: call ConfigureAuthHandler or ActivateServerMode first")
	}
	return p.mode, nil
}

// GetAuthHandlers returns the list of auth handlers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetAuthHandlers(_ context.Context) ([]sdkplugin.AuthHandlerInfo, error) {
	return []sdkplugin.AuthHandlerInfo{
		{
			Name:        HandlerName,
			DisplayName: HandlerDisplayName,
			Flows: []auth.Flow{
				auth.FlowInteractive,
				auth.FlowDeviceCode,
				auth.FlowServicePrincipal,
				auth.FlowWorkloadIdentity,
			},
			Capabilities: []auth.Capability{
				auth.CapScopesOnLogin,
				auth.CapScopesOnTokenRequest,
				auth.CapTenantID,
				auth.CapFederatedToken,
				auth.CapCallbackPort,
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes the handler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	var rawSettings []byte
	if raw, ok := cfg.Settings[HandlerName]; ok {
		rawSettings = raw
	}
	parsedCfg, err := parseHandlerConfig(rawSettings)
	if err != nil {
		return err
	}

	initKey, initClientCfg, err := resolveEffectiveHTTPConfig(parsedCfg.HTTPClient)
	if err != nil {
		return fmt.Errorf("failed to build HTTP client from httpClient config: %w", err)
	}

	p.cfg = cfg
	p.config = parsedCfg

	// Initialize clock
	p.clock = clock.Real{}

	// Cache the host client for later use
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)

	baseLgr := logr.FromContextOrDiscard(ctx)
	httpLogger := baseLgr.V(5) // high verbosity for auth HTTP

	p.clientCacheMu.Lock()
	needHTTP := p.httpClient == nil
	if !needHTTP {
		_, needHTTP = p.httpClient.(*DefaultHTTPClient)
	}
	needGraph := p.graphClient == nil
	if !needGraph {
		_, needGraph = p.graphClient.(*DefaultGraphClient)
	}
	p.clientCacheMu.Unlock()

	var nextHTTP *DefaultHTTPClient
	if needHTTP {
		nextHTTP = newDefaultHTTPClientFromResolved(initClientCfg, httpLogger)
	}
	var nextGraph *DefaultGraphClient
	if needGraph {
		nextGraph = newDefaultGraphClientFromResolved(initClientCfg, httpLogger)
	}

	var prevHTTPHandle *clientRefHandle
	var prevGraphHandle *clientRefHandle
	var unusedHTTP *DefaultHTTPClient
	var unusedGraph *DefaultGraphClient
	p.clientCacheMu.Lock()
	if nextHTTP != nil {
		if defHTTP, isDefault := p.httpClient.(*DefaultHTTPClient); isDefault {
			prevHTTPHandle = p.initHTTPHandle
			if prevHTTPHandle == nil {
				prevHTTPHandle = newClientRefHandle(defHTTP)
			}
		}
		if p.httpClient == nil || prevHTTPHandle != nil {
			p.httpClient = nextHTTP
			p.initHTTPHandle = newClientRefHandle(nextHTTP)
		} else {
			unusedHTTP = nextHTTP
		}
	}
	if nextGraph != nil {
		if defGraph, isDefault := p.graphClient.(*DefaultGraphClient); isDefault {
			prevGraphHandle = p.initGraphHandle
			if prevGraphHandle == nil {
				prevGraphHandle = newClientRefHandle(defGraph)
			}
		}
		if p.graphClient == nil || prevGraphHandle != nil {
			p.graphClient = nextGraph
			p.initGraphHandle = newClientRefHandle(nextGraph)
		} else {
			unusedGraph = nextGraph
		}
	}
	oldHTTPCache := p.httpClientCache
	oldGraphCache := p.graphClientCache
	p.baseLogger = baseLgr
	p.initHTTPKey = initKey
	p.hasInitHTTPKey = true
	p.httpClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultHTTPClient](p.clientCacheSize)
	p.graphClientCache = newBoundedClientCache[effectiveHTTPConfigKey, *DefaultGraphClient](p.clientCacheSize)
	p.clientCacheMu.Unlock()

	if oldHTTPCache != nil {
		oldHTTPCache.CloseAll()
	}
	if oldGraphCache != nil {
		oldGraphCache.CloseAll()
	}
	if prevHTTPHandle != nil {
		prevHTTPHandle.retire()
	}
	if prevGraphHandle != nil {
		prevGraphHandle.retire()
	}
	if unusedHTTP != nil {
		_ = unusedHTTP.Close()
	}
	if unusedGraph != nil {
		_ = unusedGraph.Close()
	}

	// Initialize browser opener (can be overridden for testing)
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}

	// Initialize headless detection (can be overridden for testing)
	if p.headlessReason == nil {
		p.headlessReason = defaultHeadlessReason
	}

	// Default to CLI mode, stopping any previously active stopper mode cleanly.
	prevMode := p.mode
	p.mode = &cliMode{p: p}
	if s, ok := prevMode.(interface{ Stop() }); ok {
		s.Stop()
	}

	return nil
}

// Login performs the authentication flow.
//
// Flow selection precedence:
//  1. Explicit FlowWorkloadIdentity -- uses federated token from environment.
//  2. Explicit FlowServicePrincipal -- uses client credentials from environment.
//  3. Implicit credential detection -- when no flow is specified, checks for
//     workload identity and service principal environment credentials.
//  4. Explicit FlowInteractive -- authorization code + PKCE flow.
//  5. Explicit FlowDeviceCode -- device code polling flow.
//  6. Empty flow (no credentials detected) -- config DefaultFlow when it is
//     interactive or device_code, otherwise the handler default (interactive;
//     falls back to device code when no browser is available).
//
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	ctx = attachRequestSettings(ctx, req.Settings)
	return m.Login(ctx, req, deviceCodeCb)
}

// Logout revokes the current session.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) Logout(ctx context.Context, handlerName string, _ sdkplugin.LogoutRequest) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return err
	}
	return m.Logout(ctx)
}

// logoutInternal clears stored credentials and cached tokens.
func (p *Plugin) logoutInternal(ctx context.Context) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	mu := p.profileLock(ctx)
	if err := mu.Lock(ctx); err != nil {
		return err
	}
	defer mu.Unlock()

	return p.logoutLocked(ctx, hostClient)
}

// logoutIfSessionMatches clears stored credentials only when the stored
// session metadata can be read and parsed and its SessionID still matches
// expectedSessionID. Returning without deleting on GetSecret errors, absent
// metadata, or parse failures ensures a transient read error during an old
// refresh's invalid_grant cannot wipe a newer session.
func (p *Plugin) logoutIfSessionMatches(ctx context.Context, expectedSessionID string) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil
	}

	mu := p.profileLock(ctx)
	if err := mu.Lock(ctx); err != nil {
		return err
	}
	defer mu.Unlock()

	metaRaw, found, err := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if err != nil {
		if cErr := contextErr(ctx, err); cErr != nil {
			return cErr
		}
		return nil
	}
	if !found || metaRaw == "" {
		return nil
	}
	curMeta, parseErr := p.parseMetadata(metaRaw)
	if parseErr != nil || curMeta.SessionID != expectedSessionID {
		return nil
	}

	return p.logoutLocked(ctx, hostClient)
}

func (p *Plugin) logoutLocked(ctx context.Context, hostClient *sdkplugin.HostServiceClient) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("logging out", "handler", HandlerName)

	// Delete the legacy refresh token before metadata so neither cross-process
	// readers nor ListCachedTokens can observe !metaFound with a surviving
	// legacy refresh_token key if Logout is interleaved or canceled mid-sweep.
	refreshKey := p.secretKey(ctx, secretSuffixRefreshToken)
	if err := hostClient.DeleteSecret(ctx, refreshKey); err != nil {
		if cErr := contextErr(ctx, err); cErr != nil {
			return cErr
		}
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete metadata next so the session is immediately marked logged out.
	if err := hostClient.DeleteSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); err != nil {
		if cErr := contextErr(ctx, err); cErr != nil {
			return cErr
		}
		lgr.V(1).Info("failed to delete metadata (may not exist)", "error", err)
	}

	// Clear all cached access tokens and versioned refresh revisions.
	if err := cacheClear(ctx, lgr, hostClient, p.tokenCachePrefix(ctx)); err != nil {
		return err
	}
	if err := cacheClear(ctx, lgr, hostClient, refreshKey+"."); err != nil {
		return err
	}

	return ctx.Err()
}

// GetStatus returns the current authentication status.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetStatus(ctx context.Context, handlerName string, req sdkplugin.StatusRequest) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	ctx = attachRequestSettings(ctx, req.Settings)
	return m.GetStatus(ctx)
}

// GetToken returns a valid access token, refreshing if necessary.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	ctx = attachRequestSettings(ctx, req.Settings)
	return m.GetToken(ctx, req)
}

// GetGroups returns the ObjectIDs of all Microsoft Entra groups the authenticated
// user belongs to, satisfying sdkplugin.AuthGroupsProvider for the GetGroups RPC.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) GetGroups(ctx context.Context, handlerName string) ([]string, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.GetGroups(ctx)
}

// ListCachedTokens returns metadata for all tokens stored by the Entra handler.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.ListCachedTokens(ctx)
}

// PurgeExpiredTokens removes expired access tokens and aged orphaned refresh
// revisions from the cache.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return 0, err
	}
	return m.PurgeExpiredTokens(ctx)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration.
// Delegates to the active mode (CLI mode by default).
func (p *Plugin) DetectAvailableFlows(ctx context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return nil, err
	}
	return m.DetectAvailableFlows(ctx)
}

// detectWorkloadIdentityUnavailableReason returns a specific reason why
// workload identity credentials are not available, using the same
// config-then-env resolution as the resolver.
func (p *Plugin) detectWorkloadIdentityUnavailableReason() string {
	return p.detectWorkloadIdentityUnavailableReasonForConfig(p.config)
}

func (p *Plugin) detectWorkloadIdentityUnavailableReasonForConfig(cfg *Config) string {
	if cfg == nil {
		cfg = p.config
	}
	tokenFile := cfg.profileOrEnv(cfg.FederatedTokenFile, "federatedTokenFile", EnvAzureFederatedTokenFile)
	directToken := cfg.profileOrEnv(cfg.FederatedToken, "federatedToken", EnvAzureFederatedToken)
	clientID := cfg.profileOrEnv(cfg.ClientID, "clientId", EnvAzureClientID)
	tenantID := cfg.profileOrEnv(cfg.TenantID, "tenantId", EnvAzureTenantID)

	hasTokenSource := directToken != ""
	if tokenFile != "" {
		if _, err := os.Stat(filepath.Clean(tokenFile)); err == nil { //nolint:gosec // tokenFile is from trusted config or env var
			hasTokenSource = true
		} else if !hasTokenSource {
			// Token file is set but inaccessible, and no direct token either.
			source := EnvAzureFederatedTokenFile
			if cfg.WasSet("federatedTokenFile") {
				source = "federatedTokenFile (config)"
			}
			return fmt.Sprintf("%s is set but the file is missing or inaccessible: %v", source, err)
		}
	}

	if !hasTokenSource {
		return fmt.Sprintf("neither %s nor %s is configured", EnvAzureFederatedTokenFile, EnvAzureFederatedToken)
	}

	// Token source exists but client/tenant are missing.
	var missing []string
	if clientID == "" {
		missing = append(missing, EnvAzureClientID)
	}
	if tenantID == "" {
		missing = append(missing, EnvAzureTenantID)
	}
	if len(missing) > 0 {
		return fmt.Sprintf("federated token is available but missing %s (not in config or environment)", strings.Join(missing, ", "))
	}

	return "workload identity credentials not configured"
}

// StopAuthHandler performs cleanup before plugin unload.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	m, err := p.activeMode()
	if err != nil {
		return err
	}
	type stopper interface{ Stop() }
	if s, ok := m.(stopper); ok {
		s.Stop()
	}
	p.closeHTTPClients()
	return nil
}

// hostClient returns the cached host service client or looks it up from context.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if p.cachedHostClient != nil {
		return p.cachedHostClient
	}
	return sdkplugin.HostClientFromContext(ctx)
}

// getSecret retrieves a secret value from the host secret store.
func (p *Plugin) getSecret(ctx context.Context, key string) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}
	value, found, err := hostClient.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return value, nil
}

// binaryName returns the host binary name for error messages.
func (p *Plugin) binaryName() string {
	if p.cfg.BinaryName != "" {
		return p.cfg.BinaryName
	}
	return "scafctl"
}

// secretKey returns a profile-scoped secret key. An empty context profile
// always maps to the default (unscoped) key format: there is deliberately no
// fallback to the profile configured during ConfigureAuthHandler, because the
// host resolves the active profile before the gRPC call when the active
// session is intended. A request arriving without a profile must act on the
// unscoped session (issue #44). The profile name is hex-encoded to prevent
// dot-delimited collisions (e.g. a profile named "prod.token" would otherwise
// overlap with the token cache prefix for profile "prod").
func (p *Plugin) secretKey(ctx context.Context, suffix string) string {
	profile := auth.ProfileFromContext(ctx)
	if profile == "" {
		return secretKeyBase + "." + suffix
	}
	return secretKeyBase + "." + hex.EncodeToString([]byte(profile)) + "." + suffix
}

// profileOrEnv returns the config value if its JSON field was explicitly
// provided during unmarshaling, otherwise falls back to the environment
// variable. This ensures that a profile intentionally setting a value equal
// to the default (e.g. tenantId = "common") is honored rather than overridden
// by an env var.
func (c *Config) profileOrEnv(configVal, jsonField, envVar string) string {
	if c != nil && c.WasSet(jsonField) {
		return configVal
	}
	return os.Getenv(envVar)
}

// tokenCachePrefix returns the profile-scoped prefix for cached access tokens.
func (p *Plugin) tokenCachePrefix(ctx context.Context) string {
	return p.secretKey(ctx, secretSuffixTokenPrefix)
}

// ActivateServerMode activates server mode on the plugin.
// It unmarshals the server configuration from the settings JSON and transitions
// the plugin to server mode. This method is self-contained and does not require
// ConfigureAuthHandler to be called first.
func (p *Plugin) ActivateServerMode(ctx context.Context, settings json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(settings))
	dec.DisallowUnknownFields()
	var sc ServerConfig
	if err := dec.Decode(&sc); err != nil {
		return fmt.Errorf("failed to parse server config: %w", err)
	}
	if trailing := bytes.TrimSpace(settings[dec.InputOffset():]); len(trailing) > 0 {
		return fmt.Errorf("failed to parse server config: unexpected trailing data")
	}

	if err := sc.Validate(); err != nil {
		return fmt.Errorf("server mode validation failed: %w", err)
	}

	if sc.Delegated != nil {
		if err := validateDelegatedFlow(sc.Delegated, sc.ServerFlow); err != nil {
			return fmt.Errorf("invalid delegated config: %w", err)
		}
	}

	return p.activateServerMode(ctx, &sc)
}

// activateServerMode builds and installs the server mode. Separated from
// ActivateServerMode so tests can call it directly without validation.
func (p *Plugin) activateServerMode(ctx context.Context, sc *ServerConfig) error {
	sm, err := buildServerMode(ctx, sc, nil)
	if err != nil {
		return err
	}
	prevMode := p.mode
	p.mode = sm
	if s, ok := prevMode.(interface{ Stop() }); ok {
		s.Stop()
	}
	return nil
}

// resolveServerCredential builds the appropriate ServerCredential based on the
// server flow. It uses SecretRef for all secret resolution.
func resolveServerCredential(serverFlow auth.Flow, cc *CredentialConfig) (ServerCredential, error) {
	switch serverFlow {
	case auth.FlowClientCredentials:
		secret, err := cc.ClientSecret.Resolve()
		if err != nil {
			return nil, fmt.Errorf("resolving client secret: %w", err)
		}
		return &SecretCredential{Secret: secret}, nil
	case auth.FlowWorkloadIdentity:
		_, err := cc.WIFToken.Resolve()
		if err != nil {
			return nil, fmt.Errorf("resolving WIF token: %w", err)
		}
		// WIF tokens are resolved on every Apply call (they rotate),
		// so we pass the SecretRef directly.
		return &WIFCredential{
			Token:               cc.WIFToken,
			ClientAssertionType: clientAssertionType,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported server flow: %s", serverFlow)
	}
}
