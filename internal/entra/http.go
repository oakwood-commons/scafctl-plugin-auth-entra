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
	allowPrivateIPs                   bool
	maxResponseBodySize               int64
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
		allowPrivateIPs:      cfg.AllowPrivateIPs,
		maxResponseBodySize:  cfg.MaxResponseBodySize,
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
	if merged.AllowPrivateIPs != nil {
		clientCfg.AllowPrivateIPs = *merged.AllowPrivateIPs
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
	cfgCopy.Logger = logger
	cfgCopy.Transport = tr
	return &cfgCopy
}

// boundedClientCache is a concurrency-safe, size-bounded LRU cache of closable
// HTTP/Graph clients. Evicted or cleared entries have Close() invoked outside
// the cache mutex so idle transport connections and cache handles are released
// without blocking concurrent lookups.
type boundedClientCache[K comparable, V io.Closer] struct {
	mu       sync.Mutex
	capacity int
	store    map[K]*list.Element
	order    *list.List
}

type clientCacheEntry[K comparable, V io.Closer] struct {
	key   K
	value V
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

func (c *boundedClientCache[K, V]) GetOrCreate(key K, build func() V) V {
	c.mu.Lock()
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		val := elem.Value.(*clientCacheEntry[K, V]).value
		c.mu.Unlock()
		return val
	}
	c.mu.Unlock()

	candidate := build()

	c.mu.Lock()
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		winner := elem.Value.(*clientCacheEntry[K, V]).value
		c.mu.Unlock()
		_ = candidate.Close()
		return winner
	}

	elem := c.order.PushFront(&clientCacheEntry[K, V]{key: key, value: candidate})
	c.store[key] = elem

	var evicted V
	var hasEvicted bool
	if c.order.Len() > c.capacity {
		if oldest := c.order.Back(); oldest != nil {
			entry := oldest.Value.(*clientCacheEntry[K, V])
			delete(c.store, entry.key)
			c.order.Remove(oldest)
			evicted = entry.value
			hasEvicted = true
		}
	}
	c.mu.Unlock()

	if hasEvicted {
		_ = evicted.Close()
	}
	return candidate
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
	toClose := make([]V, 0, c.order.Len())
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		toClose = append(toClose, elem.Value.(*clientCacheEntry[K, V]).value)
	}
	c.store = make(map[K]*list.Element, c.capacity)
	c.order.Init()
	c.mu.Unlock()

	for _, client := range toClose {
		_ = client.Close()
	}
}

// DefaultGraphClient implements GraphClient using httpc.
type DefaultGraphClient struct {
	client    *httpc.Client
	transport *http.Transport
}

func newDefaultGraphClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultGraphClient {
	tr := newIsolatedTransport()
	return &DefaultGraphClient{
		client:    httpc.NewClient(cloneResolvedClientConfig(baseCfg, logger, tr)),
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
}

func newDefaultHTTPClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultHTTPClient {
	tr := newIsolatedTransport()
	return &DefaultHTTPClient{
		client:    httpc.NewClient(cloneResolvedClientConfig(baseCfg, logger, tr)),
		transport: tr,
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
