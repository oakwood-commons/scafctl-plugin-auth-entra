// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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
	defaultHTTPTimeout         = 30 * time.Second
	defaultHTTPRetryMax        = 3
	defaultHTTPRetryWaitFloor  = 1 * time.Second
	defaultHTTPRetryWaitMax    = 10 * time.Second
	defaultHTTPClientCacheSize = 32
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

// effectiveHTTPConfigKey is a comparable canonical representation of a merged
// httpc.ClientConfig so semantically equivalent per-RPC httpClient settings
// share a single cached client (preserving connection pools and circuit-breaker
// state across RPCs).
type effectiveHTTPConfigKey struct {
	timeout                           time.Duration
	retryMax                          int
	retryWaitMin                      time.Duration
	retryWaitMax                      time.Duration
	enableCache                       bool
	cacheType                         httpc.CacheType
	cacheDir                          string
	cacheTTL                          time.Duration
	cacheKeyPrefix                    string
	maxCacheFileSize                  int64
	memoryCacheSize                   int
	enableCircuitBreaker              bool
	circuitBreakerMaxFailures         int
	circuitBreakerOpenTimeout         time.Duration
	circuitBreakerHalfOpenMaxRequests int
	enableCompression                 bool
	allowPrivate                      bool
	trustProxyResolution              bool
	allowedCIDRs                      string
	maxResponseBodySize               int64
	noRetry                           bool
}

// withoutRetries marks k for callers whose higher-level polling loop schedules
// every retry (such as OAuth device-code token exchanges) and must not run
// transport-level HTTP retries.
func (k effectiveHTTPConfigKey) withoutRetries() effectiveHTTPConfigKey {
	k.noRetry = true
	k.retryMax = 0
	k.retryWaitMin = 0
	k.retryWaitMax = 0
	return k
}

// withoutHTTPCache zeroes response-cache fields on k for DefaultGraphClient,
// which always disables HTTP response caching so identity-scoped Graph
// responses can never bleed across profiles or sessions.
func (k effectiveHTTPConfigKey) withoutHTTPCache() effectiveHTTPConfigKey {
	k.enableCache = false
	k.cacheType = ""
	k.cacheDir = ""
	k.cacheTTL = 0
	k.cacheKeyPrefix = ""
	k.maxCacheFileSize = 0
	k.memoryCacheSize = 0
	return k
}

func effectiveHTTPConfigKeyFromClientConfig(cfg *httpc.ClientConfig) effectiveHTTPConfigKey {
	k := effectiveHTTPConfigKey{
		timeout:              cfg.Timeout,
		retryMax:             cfg.RetryMax,
		retryWaitMin:         cfg.RetryWaitMin,
		retryWaitMax:         cfg.RetryWaitMax,
		enableCache:          cfg.EnableCache,
		enableCircuitBreaker: cfg.EnableCircuitBreaker,
		enableCompression:    cfg.EnableCompression,
		maxResponseBodySize:  cfg.MaxResponseBodySize,
	}
	if cfg.IPPolicy != nil {
		k.allowPrivate = cfg.IPPolicy.AllowPrivate
		k.trustProxyResolution = cfg.IPPolicy.TrustProxyResolution
		if !cfg.IPPolicy.AllowPrivate && len(cfg.IPPolicy.AllowedCIDRs) > 0 {
			cidrs := make([]string, 0, len(cfg.IPPolicy.AllowedCIDRs))
			for _, n := range cfg.IPPolicy.AllowedCIDRs {
				if n != nil {
					cidrs = append(cidrs, n.String())
				}
			}
			slices.Sort(cidrs)
			cidrs = slices.Compact(cidrs)
			k.allowedCIDRs = strings.Join(cidrs, ",")
		}
	}
	if cfg.EnableCache {
		k.cacheType = cfg.CacheType
		k.cacheTTL = cfg.CacheTTL
		if cfg.CacheType == httpc.CacheTypeFilesystem {
			k.cacheDir = cfg.CacheDir
			k.cacheKeyPrefix = cfg.CacheKeyPrefix
			k.maxCacheFileSize = cfg.MaxCacheFileSize
		} else {
			k.memoryCacheSize = cfg.MemoryCacheSize
		}
	}
	if cfg.EnableCircuitBreaker && cfg.CircuitBreakerConfig != nil {
		k.circuitBreakerMaxFailures = cfg.CircuitBreakerConfig.MaxFailures
		k.circuitBreakerOpenTimeout = cfg.CircuitBreakerConfig.OpenTimeout
		k.circuitBreakerHalfOpenMaxRequests = cfg.CircuitBreakerConfig.HalfOpenMaxRequests
	}
	return k
}

// resolveEffectiveHTTPConfig merges plugin defaults with cfg, validates all
// duration and enum fields using the same rules as httpc.NewClientFromAppConfig,
// and returns both the canonical cache key and the resolved ClientConfig.
func resolveEffectiveHTTPConfig(cfg *httpc.AppConfig) (effectiveHTTPConfigKey, *httpc.ClientConfig, error) {
	merged := mergeHTTPClientDefaults(cfg)
	clientCfg := httpc.DefaultConfig()

	if merged.Timeout != "" {
		d, err := time.ParseDuration(merged.Timeout)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid timeout duration %q: %w", merged.Timeout, err)
		}
		clientCfg.Timeout = d
	}
	if merged.RetryMax > 0 {
		clientCfg.RetryMax = merged.RetryMax
	}
	if merged.RetryWaitMin != "" {
		d, err := time.ParseDuration(merged.RetryWaitMin)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMin duration %q: %w", merged.RetryWaitMin, err)
		}
		clientCfg.RetryWaitMin = d
	}
	if merged.RetryWaitMax != "" {
		d, err := time.ParseDuration(merged.RetryWaitMax)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMax duration %q: %w", merged.RetryWaitMax, err)
		}
		clientCfg.RetryWaitMax = d
	}
	if merged.EnableCache != nil {
		clientCfg.EnableCache = *merged.EnableCache
	}
	if merged.CacheType != "" {
		ct := httpc.CacheType(merged.CacheType)
		if ct != httpc.CacheTypeMemory && ct != httpc.CacheTypeFilesystem {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheType %q: must be %q or %q", merged.CacheType, httpc.CacheTypeMemory, httpc.CacheTypeFilesystem)
		}
		clientCfg.CacheType = ct
	}
	if merged.CacheDir != "" {
		clientCfg.CacheDir = merged.CacheDir
	}
	if merged.CacheTTL != "" {
		d, err := time.ParseDuration(merged.CacheTTL)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheTTL duration %q: %w", merged.CacheTTL, err)
		}
		clientCfg.CacheTTL = d
	}
	if merged.CacheKeyPrefix != "" {
		clientCfg.CacheKeyPrefix = merged.CacheKeyPrefix
	}
	if merged.MaxCacheFileSize > 0 {
		clientCfg.MaxCacheFileSize = merged.MaxCacheFileSize
	}
	if merged.MemoryCacheSize > 0 {
		clientCfg.MemoryCacheSize = merged.MemoryCacheSize
	}
	if merged.EnableCircuitBreaker != nil {
		clientCfg.EnableCircuitBreaker = *merged.EnableCircuitBreaker
	}
	if merged.CircuitBreakerMaxFailures > 0 || merged.CircuitBreakerOpenTimeout != "" || merged.CircuitBreakerHalfOpenMaxRequests > 0 {
		clientCfg.CircuitBreakerConfig = httpc.DefaultCircuitBreakerConfig()
		if merged.CircuitBreakerMaxFailures > 0 {
			clientCfg.CircuitBreakerConfig.MaxFailures = merged.CircuitBreakerMaxFailures
		}
		if merged.CircuitBreakerOpenTimeout != "" {
			d, err := time.ParseDuration(merged.CircuitBreakerOpenTimeout)
			if err != nil {
				return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid circuitBreakerOpenTimeout duration %q: %w", merged.CircuitBreakerOpenTimeout, err)
			}
			clientCfg.CircuitBreakerConfig.OpenTimeout = d
		}
		if merged.CircuitBreakerHalfOpenMaxRequests > 0 {
			clientCfg.CircuitBreakerConfig.HalfOpenMaxRequests = merged.CircuitBreakerHalfOpenMaxRequests
		}
	}
	if merged.EnableCompression != nil {
		clientCfg.EnableCompression = *merged.EnableCompression
	}
	if merged.AllowPrivateIPs != nil && *merged.AllowPrivateIPs { //nolint:staticcheck // SA1019: honor legacy allowPrivateIPs config field when allowedPrivateCIDRs is unset
		clientCfg.IPPolicy = httpc.AllowAllPrivateIPs()
	}
	if merged.AllowedPrivateCIDRs != nil {
		policy, err := httpc.NewIPPolicy(merged.AllowedPrivateCIDRs...)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid allowedPrivateCIDRs: %w", err)
		}
		clientCfg.IPPolicy = policy
	}
	if merged.TrustProxyResolution != nil {
		var policy httpc.IPPolicy
		if clientCfg.IPPolicy != nil {
			policy = *clientCfg.IPPolicy
		}
		policy.TrustProxyResolution = *merged.TrustProxyResolution
		clientCfg.IPPolicy = &policy
	}
	if merged.MaxResponseBodySize > 0 {
		clientCfg.MaxResponseBodySize = merged.MaxResponseBodySize
	}

	return effectiveHTTPConfigKeyFromClientConfig(clientCfg), clientCfg, nil
}

func newIsolatedTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
		return dt.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func cloneResolvedClientConfig(baseCfg *httpc.ClientConfig, logger logr.Logger, tr *http.Transport) *httpc.ClientConfig {
	cfgCopy := *baseCfg
	if baseCfg.CircuitBreakerConfig != nil {
		cbCopy := *baseCfg.CircuitBreakerConfig
		cfgCopy.CircuitBreakerConfig = &cbCopy
	}
	if baseCfg.IPPolicy != nil {
		ipCopy := *baseCfg.IPPolicy
		if baseCfg.IPPolicy.AllowedCIDRs != nil {
			ipCopy.AllowedCIDRs = slices.Clone(baseCfg.IPPolicy.AllowedCIDRs)
		}
		cfgCopy.IPPolicy = &ipCopy
	}
	cfgCopy.Logger = logger
	cfgCopy.Transport = tr
	return &cfgCopy
}

func noopRelease() {}

// clientRefHandle tracks active borrowers of a closable HTTP/Graph client so
// cache eviction, reconfiguration, or shutdown defers Close() until the last
// in-flight borrower releases its reference.
type clientRefHandle struct {
	mu      sync.Mutex
	closer  io.Closer
	refs    int
	retired bool
	closed  bool
}

func newClientRefHandle(closer io.Closer) *clientRefHandle {
	return &clientRefHandle{closer: closer}
}

func (h *clientRefHandle) tryAcquire() (func(), bool) {
	if h == nil {
		return noopRelease, false
	}
	h.mu.Lock()
	if h.retired || h.closed {
		h.mu.Unlock()
		return noopRelease, false
	}
	h.refs++
	h.mu.Unlock()
	return h.releaseFunc(), true
}

func (h *clientRefHandle) acquireFresh() func() {
	h.mu.Lock()
	h.refs++
	h.mu.Unlock()
	return h.releaseFunc()
}

func (h *clientRefHandle) releaseFunc() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.refs--
			shouldClose := h.retired && h.refs == 0 && !h.closed
			if shouldClose {
				h.closed = true
			}
			closer := h.closer
			h.mu.Unlock()

			if shouldClose && closer != nil {
				_ = closer.Close()
			}
		})
	}
}

func (h *clientRefHandle) retire() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.retired = true
	shouldClose := h.refs == 0 && !h.closed
	if shouldClose {
		h.closed = true
	}
	closer := h.closer
	h.mu.Unlock()

	if shouldClose && closer != nil {
		_ = closer.Close()
	}
}

// boundedClientCache is a concurrency-safe, size-bounded LRU cache of closable
// HTTP/Graph clients. Borrowers acquire a reference lease via Acquire; evicted
// or cleared entries defer Close() until all active borrowers release their
// leases so requests issued after eviction never leak keep-alive connections.
type boundedClientCache[K comparable, V io.Closer] struct {
	mu       sync.Mutex
	capacity int
	closed   bool
	store    map[K]*list.Element
	order    *list.List
}

type clientCacheEntry[K comparable, V io.Closer] struct {
	key    K
	value  V
	handle *clientRefHandle
}

func newBoundedClientCache[K comparable, V io.Closer](capacity int) *boundedClientCache[K, V] {
	if capacity <= 0 {
		capacity = defaultHTTPClientCacheSize
	}
	return &boundedClientCache[K, V]{
		capacity: capacity,
		store:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *boundedClientCache[K, V]) Acquire(key K, build func() V) (V, func()) {
	c.mu.Lock()
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		entry := elem.Value.(*clientCacheEntry[K, V])
		rel, acquired := entry.handle.tryAcquire()
		if acquired {
			val := entry.value
			c.mu.Unlock()
			return val, rel
		}
	}
	c.mu.Unlock()

	candidate := build()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		h := newClientRefHandle(candidate)
		rel := h.acquireFresh()
		h.retire()
		return candidate, rel
	}
	if elem, ok := c.store[key]; ok {
		entry := elem.Value.(*clientCacheEntry[K, V])
		if rel, acquired := entry.handle.tryAcquire(); acquired {
			c.order.MoveToFront(elem)
			winner := entry.value
			c.mu.Unlock()
			_ = candidate.Close()
			return winner, rel
		}
		delete(c.store, entry.key)
		c.order.Remove(elem)
	}

	h := newClientRefHandle(candidate)
	rel := h.acquireFresh()
	elem := c.order.PushFront(&clientCacheEntry[K, V]{key: key, value: candidate, handle: h})
	c.store[key] = elem

	var evictedHandle *clientRefHandle
	if c.order.Len() > c.capacity {
		if oldest := c.order.Back(); oldest != nil {
			victim := oldest.Value.(*clientCacheEntry[K, V])
			delete(c.store, victim.key)
			c.order.Remove(oldest)
			evictedHandle = victim.handle
		}
	}
	c.mu.Unlock()

	if evictedHandle != nil {
		evictedHandle.retire()
	}
	return candidate, rel
}

func (c *boundedClientCache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *boundedClientCache[K, V]) CloseAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	handles := make([]*clientRefHandle, 0, c.order.Len())
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		handles = append(handles, elem.Value.(*clientCacheEntry[K, V]).handle)
	}
	c.store = make(map[K]*list.Element, c.capacity)
	c.order.Init()
	c.mu.Unlock()

	for _, h := range handles {
		h.retire()
	}
}

// DefaultGraphClient implements GraphClient using httpc.
type DefaultGraphClient struct {
	client    *httpc.Client
	transport *http.Transport
}

func newDefaultGraphClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultGraphClient {
	tr := newIsolatedTransport()
	cfg := cloneResolvedClientConfig(baseCfg, logger, tr)
	// Graph /me/memberOf responses are scoped to the caller's delegated Bearer
	// token, whereas httpcache keys GET responses by URL alone; keep HTTP
	// response caching disabled so group memberships never bleed across profiles.
	cfg.EnableCache = false
	return &DefaultGraphClient{
		client:    httpc.NewClient(cfg),
		transport: tr,
	}
}

// NewDefaultGraphClient creates a new Graph API HTTP client. Forwarded
// auth.entra.httpClient settings overlay the plugin defaults; nil keeps them.
func NewDefaultGraphClient(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultGraphClient, error) {
	_, clientCfg, err := resolveEffectiveHTTPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newDefaultGraphClientFromResolved(clientCfg, logger), nil
}

// Close releases idle HTTP connections and any underlying cache resources.
func (c *DefaultGraphClient) Close() error {
	if c == nil {
		return nil
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
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
	client    *httpc.Client
	transport *http.Transport
	baseCfg   *httpc.ClientConfig
	baseKey   effectiveHTTPConfigKey
}

func newDefaultHTTPClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultHTTPClient {
	tr := newIsolatedTransport()
	resolvedCopy := cloneResolvedClientConfig(baseCfg, logger, nil)
	return &DefaultHTTPClient{
		client:    httpc.NewClient(cloneResolvedClientConfig(baseCfg, logger, tr)),
		transport: tr,
		baseCfg:   resolvedCopy,
		baseKey:   effectiveHTTPConfigKeyFromClientConfig(resolvedCopy),
	}
}

func newDefaultNoRetryHTTPClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultHTTPClient {
	tr := newIsolatedTransport()
	cfg := cloneResolvedClientConfig(baseCfg, logger, tr)
	cfg.RetryMax = 0
	cfg.RetryWaitMin = 0
	cfg.RetryWaitMax = 0
	cfg.CheckRetry = func(_ context.Context, _ *http.Response, _ error) (bool, error) {
		return false, nil
	}
	cfg.ErrorHandler = func(resp *http.Response, err error, _ int) (*http.Response, error) {
		if err != nil && resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			return nil, err
		}
		return resp, err
	}
	resolvedCopy := cloneResolvedClientConfig(cfg, logger, nil)
	return &DefaultHTTPClient{
		client:    httpc.NewClient(cfg),
		transport: tr,
		baseCfg:   resolvedCopy,
		baseKey:   effectiveHTTPConfigKeyFromClientConfig(resolvedCopy).withoutRetries(),
	}
}

// NewDefaultHTTPClient creates a new default HTTP client backed by httpc.
// Forwarded auth.entra.httpClient settings overlay the plugin defaults; nil
// keeps them.
func NewDefaultHTTPClient(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultHTTPClient, error) {
	_, clientCfg, err := resolveEffectiveHTTPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newDefaultHTTPClientFromResolved(clientCfg, logger), nil
}

// Close releases idle HTTP connections and any underlying cache resources.
func (c *DefaultHTTPClient) Close() error {
	if c == nil {
		return nil
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
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
