// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http/httpguts"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a highly configurable and production-ready reverse proxy.
//
// Upon proxying, this module sets the following placeholders (which can be used
// both within and after this handler; for example, in response headers):
//
// Placeholder | Description
// ------------|-------------
// `{http.reverse_proxy.upstream.address}` | The full address to the upstream as given in the config
// `{http.reverse_proxy.upstream.hostport}` | The host:port of the upstream
// `{http.reverse_proxy.upstream.host}` | The host of the upstream
// `{http.reverse_proxy.upstream.port}` | The port of the upstream
// `{http.reverse_proxy.upstream.requests}` | The approximate current number of requests to the upstream
// `{http.reverse_proxy.upstream.max_requests}` | The maximum approximate number of requests allowed to the upstream
// `{http.reverse_proxy.upstream.fails}` | The number of recent failed requests to the upstream
// `{http.reverse_proxy.upstream.latency}` | How long it took the proxy upstream to write the response header.
// `{http.reverse_proxy.upstream.latency_ms}` | Same as 'latency', but in milliseconds.
// `{http.reverse_proxy.upstream.duration}` | Time spent proxying to the upstream, including writing response body to client.
// `{http.reverse_proxy.upstream.duration_ms}` | Same as 'upstream.duration', but in milliseconds.
// `{http.reverse_proxy.duration}` | Total time spent proxying, including selecting an upstream, retries, and writing response.
// `{http.reverse_proxy.duration_ms}` | Same as 'duration', but in milliseconds.
// `{http.reverse_proxy.retries}` | The number of retries actually performed to communicate with an upstream.
type Handler struct {
	// Configures the method of transport for the proxy. A transport
	// is what performs the actual "round trip" to the backend.
	// The default transport is plaintext HTTP.
	TransportRaw json.RawMessage `json:"transport,omitempty" caddy:"namespace=http.reverse_proxy.transport inline_key=protocol"`

	// A circuit breaker may be used to relieve pressure on a backend
	// that is beginning to exhibit symptoms of stress or latency.
	// By default, there is no circuit breaker.
	CBRaw json.RawMessage `json:"circuit_breaker,omitempty" caddy:"namespace=http.reverse_proxy.circuit_breakers inline_key=type"`

	// Load balancing distributes load/requests between backends.
	LoadBalancing *LoadBalancing `json:"load_balancing,omitempty"`

	// Health checks update the status of backends, whether they are
	// up or down. Down backends will not be proxied to.
	HealthChecks *HealthChecks `json:"health_checks,omitempty"`

	// Upstreams is the static list of backends to proxy to.
	Upstreams UpstreamPool `json:"upstreams,omitempty"`

	// A module for retrieving the list of upstreams dynamically. Dynamic
	// upstreams are retrieved at every iteration of the proxy loop for
	// each request (i.e. before every proxy attempt within every request).
	// Active health checks do not work on dynamic upstreams, and passive
	// health checks are only effective on dynamic upstreams if the proxy
	// server is busy enough that concurrent requests to the same backends
	// are continuous. Instead of health checks for dynamic upstreams, it
	// is recommended that the dynamic upstream module only return available
	// backends in the first place.
	DynamicUpstreamsRaw json.RawMessage `json:"dynamic_upstreams,omitempty" caddy:"namespace=http.reverse_proxy.upstreams inline_key=source"`

	// Adjusts how often to flush the response buffer. By default,
	// no periodic flushing is done. A negative value disables
	// response buffering, and flushes immediately after each
	// write to the client. This option is ignored when the upstream's
	// response is recognized as a streaming response, or if its
	// content length is -1; for such responses, writes are flushed
	// to the client immediately.
	FlushInterval caddy.Duration `json:"flush_interval,omitempty"`

	// A list of IP ranges (supports CIDR notation) from which
	// X-Forwarded-* header values should be trusted. By default,
	// no proxies are trusted, so existing values will be ignored
	// when setting these headers. If the proxy is trusted, then
	// existing values will be used when constructing the final
	// header values.
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// Headers manipulates headers between Caddy and the backend.
	// By default, all headers are passed-thru without changes,
	// with the exceptions of special hop-by-hop headers.
	//
	// X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host
	// are also set implicitly.
	Headers *headers.Handler `json:"headers,omitempty"`

	// If nonzero, the entire request body up to this size will be read
	// and buffered in memory before being proxied to the backend. This
	// should be avoided if at all possible for performance reasons, but
	// could be useful if the backend is intolerant of read latency or
	// chunked encodings.
	RequestBuffers int64 `json:"request_buffers,omitempty"`

	// If nonzero, the entire response body up to this size will be read
	// and buffered in memory before being proxied to the client. This
	// should be avoided if at all possible for performance reasons, but
	// could be useful if the backend has tighter memory constraints.
	ResponseBuffers int64 `json:"response_buffers,omitempty"`

	// If nonzero, streaming requests such as WebSockets will be
	// forcibly closed at the end of the timeout. Default: no timeout.
	StreamTimeout caddy.Duration `json:"stream_timeout,omitempty"`

	// If nonzero, streaming requests such as WebSockets will not be
	// closed when the proxy config is unloaded, and instead the stream
	// will remain open until the delay is complete. In other words,
	// enabling this prevents streams from closing when Caddy's config
	// is reloaded. Enabling this may be a good idea to avoid a thundering
	// herd of reconnecting clients which had their connections closed
	// by the previous config closing. Default: no delay.
	StreamCloseDelay caddy.Duration `json:"stream_close_delay,omitempty"`

	// If configured, rewrites the copy of the upstream request.
	// Allows changing the request method and URI (path and query).
	// Since the rewrite is applied to the copy, it does not persist
	// past the reverse proxy handler.
	// If the method is changed to `GET` or `HEAD`, the request body
	// will not be copied to the backend. This allows a later request
	// handler -- either in a `handle_response` route, or after -- to
	// read the body.
	// By default, no rewrite is performed, and the method and URI
	// from the incoming request is used as-is for proxying.
	Rewrite *rewrite.Rewrite `json:"rewrite,omitempty"`

	// List of handlers and their associated matchers to evaluate
	// after successful roundtrips. The first handler that matches
	// the response from a backend will be invoked. The response
	// body from the backend will not be written to the client;
	// it is up to the handler to finish handling the response.
	// If passive health checks are enabled, any errors from the
	// handler chain will not affect the health status of the
	// backend.
	//
	// Three new placeholders are available in this handler chain:
	// - `{http.reverse_proxy.status_code}` The status code from the response
	// - `{http.reverse_proxy.status_text}` The status text from the response
	// - `{http.reverse_proxy.header.*}` The headers from the response
	HandleResponse []caddyhttp.ResponseHandler `json:"handle_response,omitempty"`

	// If set, the proxy will write very detailed logs about its
	// inner workings. Enable this only when debugging, as it
	// will produce a lot of output.
	//
	// EXPERIMENTAL: This feature is subject to change or removal.
	VerboseLogs bool `json:"verbose_logs,omitempty"`

	Transport        http.RoundTripper `json:"-"`
	CB               CircuitBreaker    `json:"-"`
	DynamicUpstreams UpstreamSource    `json:"-"`

	// Holds the parsed CIDR ranges from TrustedProxies
	trustedProxies []netip.Prefix

	// Holds the named response matchers from the Caddyfile while adapting
	responseMatchers map[string]caddyhttp.ResponseMatcher

	// Holds the handle_response Caddyfile tokens while adapting
	handleResponseSegments []*caddyfile.Dispenser

	// Stores upgraded requests (hijacked connections) for proper cleanup
	connections           map[io.ReadWriteCloser]openConnection
	connectionsCloseTimer *time.Timer
	connectionsMu         *sync.Mutex

	ctx    caddy.Context
	logger *zap.Logger
	events *caddyevents.App
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.reverse_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	eventAppIface, err := ctx.App("events")
	if err != nil {
		return fmt.Errorf("getting events app: %v", err)
	}
	h.events = eventAppIface.(*caddyevents.App)
	h.ctx = ctx
	h.logger = ctx.Logger()
	h.connections = make(map[io.ReadWriteCloser]openConnection)
	h.connectionsMu = new(sync.Mutex)

	// warn about unsafe buffering config
	if h.RequestBuffers == -1 || h.ResponseBuffers == -1 {
		h.logger.Warn("UNLIMITED BUFFERING: buffering is enabled without any cap on buffer size, which can result in OOM crashes")
	}

	// start by loading modules
	if h.TransportRaw != nil {
		mod, err := ctx.LoadModule(h, "TransportRaw")
		if err != nil {
			return fmt.Errorf("loading transport: %v", err)
		}
		h.Transport = mod.(http.RoundTripper)
		// enable request buffering for fastcgi if not configured
		// This is because most fastcgi servers are php-fpm that require the content length to be set to read the body, golang
		// std has fastcgi implementation that doesn't need this value to process the body, but we can safely assume that's
		// not used.
		// http3 requests have a negative content length for GET and HEAD requests, if that header is not sent.
		// see: https://github.com/caddyserver/caddy/issues/6678#issuecomment-2472224182
		// Though it appears even if CONTENT_LENGTH is invalid, php-fpm can handle just fine if the body is empty (no Stdin records sent).
		// php-fpm will hang if there is any data in the body though, https://github.com/caddyserver/caddy/issues/5420#issuecomment-2415943516

		// TODO: better default buffering for fastcgi requests without content length, in theory a value of 1 should be enough, make it bigger anyway
		if module, ok := h.Transport.(caddy.Module); ok && module.CaddyModule().ID.Name() == "fastcgi" && h.RequestBuffers == 0 {
			h.RequestBuffers = 4096
		}
	}
	if h.LoadBalancing != nil && h.LoadBalancing.SelectionPolicyRaw != nil {
		mod, err := ctx.LoadModule(h.LoadBalancing, "SelectionPolicyRaw")
		if err != nil {
			return fmt.Errorf("loading load balancing selection policy: %s", err)
		}
		h.LoadBalancing.SelectionPolicy = mod.(Selector)
	}
	if h.CBRaw != nil {
		mod, err := ctx.LoadModule(h, "CBRaw")
		if err != nil {
			return fmt.Errorf("loading circuit breaker: %s", err)
		}
		h.CB = mod.(CircuitBreaker)
	}
	if h.DynamicUpstreamsRaw != nil {
		mod, err := ctx.LoadModule(h, "DynamicUpstreamsRaw")
		if err != nil {
			return fmt.Errorf("loading upstream source module: %v", err)
		}
		h.DynamicUpstreams = mod.(UpstreamSource)
	}

	// parse trusted proxy CIDRs ahead of time
	for _, str := range h.TrustedProxies {
		if strings.Contains(str, "/") {
			ipNet, err := netip.ParsePrefix(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: '%s': %v", str, err)
			}
			h.trustedProxies = append(h.trustedProxies, ipNet)
		} else {
			ipAddr, err := netip.ParseAddr(str)
			if err != nil {
				return fmt.Errorf("invalid IP address: '%s': %v", str, err)
			}
			ipNew := netip.PrefixFrom(ipAddr, ipAddr.BitLen())
			h.trustedProxies = append(h.trustedProxies, ipNew)
		}
	}

	// ensure any embedded headers handler module gets provisioned
	// (see https://caddy.community/t/set-cookie-manipulation-in-reverse-proxy/7666?u=matt
	// for what happens if we forget to provision it)
	if h.Headers != nil {
		err := h.Headers.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning embedded headers handler: %v", err)
		}
	}

	if h.Rewrite != nil {
		err := h.Rewrite.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning rewrite: %v", err)
		}
	}

	// set up transport
	if h.Transport == nil {
		t := &HTTPTransport{}
		err := t.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning default transport: %v", err)
		}
		h.Transport = t
	}

	// set up load balancing
	if h.LoadBalancing == nil {
		h.LoadBalancing = new(LoadBalancing)
	}
	if h.LoadBalancing.SelectionPolicy == nil {
		h.LoadBalancing.SelectionPolicy = RandomSelection{}
	}
	if h.LoadBalancing.TryDuration > 0 && h.LoadBalancing.TryInterval == 0 {
		// a non-zero try_duration with a zero try_interval
		// will always spin the CPU for try_duration if the
		// upstream is local or low-latency; avoid that by
		// defaulting to a sane wait period between attempts
		h.LoadBalancing.TryInterval = caddy.Duration(250 * time.Millisecond)
	}
	lbMatcherSets, err := ctx.LoadModule(h.LoadBalancing, "RetryMatchRaw")
	if err != nil {
		return err
	}
	err = h.LoadBalancing.RetryMatch.FromInterface(lbMatcherSets)
	if err != nil {
		return err
	}

	// set up upstreams
	for _, u := range h.Upstreams {
		h.provisionUpstream(u)
	}

	if h.HealthChecks != nil {
		// set defaults on passive health checks, if necessary
		if h.HealthChecks.Passive != nil {
			h.HealthChecks.Passive.logger = h.logger.Named("health_checker.passive")
			if h.HealthChecks.Passive.MaxFails == 0 {
				h.HealthChecks.Passive.MaxFails = 1
			}
		}

		// if active health checks are enabled, configure them and start a worker
		if h.HealthChecks.Active != nil {
			err := h.HealthChecks.Active.Provision(ctx, h)
			if err != nil {
				return err
			}

			if h.HealthChecks.Active.IsEnabled() {
				go h.activeHealthChecker()
			}
		}
	}

	// set up any response routes
	for i, rh := range h.HandleResponse {
		err := rh.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning response handler %d: %v", i, err)
		}
	}

	upstreamHealthyUpdater := newMetricsUpstreamsHealthyUpdater(h, ctx)
	upstreamHealthyUpdater.init()

	return nil
}

// Cleanup cleans up the resources made by h.
func (h *Handler) Cleanup() error {
	err := h.cleanupConnections()

	// remove hosts from our config from the pool
	for _, upstream := range h.Upstreams {
		_, _ = hosts.Delete(upstream.String())
	}

	return err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// prepare the request for proxying; this is needed only once
	clonedReq, err := h.prepareRequest(r, repl)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("preparing request for upstream round-trip: %v", err))
	}

	// websocket over http2 or http3 if extended connect is enabled, assuming backend doesn't support this, the request will be modified to http1.1 upgrade
	// Both use the same upgrade mechanism: server advertizes extended connect support, and client sends the pseudo header :protocol in a CONNECT request
	// The quic-go http3 implementation also puts :protocol in r.Proto for CONNECT requests (quic-go/http3/headers.go@70-72,185,203)
	// TODO: once we can reliably detect backend support this, it can be removed for those backends
	/*
		HTTP/2 / HTTP/3 的 Extended CONNECT（RFC 8441）允许客户端在 HTTP/2/3 上通过发送 CONNECT 请求并带上伪头 :protocol: websocket 来建立 WebSocket（或其它协议）隧道，而不是使用传统的 HTTP/1.1 的 GET + Upgrade: websocket 握手。
		许多后端（上游）并不支持在 HTTP/2/3 上的 extended CONNECT（它们期望 HTTP/1.1 的 Upgrade 语义）。因此当 Caddy 接到一个来自客户端的 extended CONNECT 请求时，
		如果假定上游不支持 extended CONNECT，则需要把该请求“转换”为传统的 HTTP/1.1 WebSocket Upgrade 请求去代理给后端。
		下面的代码就是做这样的转换（把 EXTENDED CONNECT 转成 HTTP/1.1 的 GET + Upgrade）
	*/
	if (r.ProtoMajor == 2 && r.Method == http.MethodConnect && r.Header.Get(":protocol") == "websocket") ||
		(r.ProtoMajor == 3 && r.Method == http.MethodConnect && r.Proto == "websocket") {
		clonedReq.Header.Del(":protocol")
		// keep the body for later use. http1.1 upgrade uses http.NoBody
		caddyhttp.SetVar(clonedReq.Context(), "extended_connect_websocket_body", clonedReq.Body)
		clonedReq.Body = http.NoBody
		clonedReq.Method = http.MethodGet
		clonedReq.Header.Set("Upgrade", "websocket")
		clonedReq.Header.Set("Connection", "Upgrade")
		key := make([]byte, 16)
		_, randErr := rand.Read(key)
		if randErr != nil {
			return randErr
		}
		clonedReq.Header["Sec-WebSocket-Key"] = []string{base64.StdEncoding.EncodeToString(key)}
	}

	// we will need the original headers and Host value if
	// header operations are configured; this is so that each
	// retry can apply the modifications, because placeholders
	// may be used which depend on the selected upstream for
	// their values
	reqHost := clonedReq.Host
	reqHeader := clonedReq.Header

	start := time.Now()
	defer func() {
		// total proxying duration, including time spent on LB and retries
		repl.Set("http.reverse_proxy.duration", time.Since(start))
		repl.Set("http.reverse_proxy.duration_ms", time.Since(start).Seconds()*1e3) // multiply seconds to preserve decimal (see #4666)
	}()

	// in the proxy loop, each iteration is an attempt to proxy the request,
	// and because we may retry some number of times, carry over the error
	// from previous tries because of the nuances of load balancing & retries
	var proxyErr error
	var retries int
	for {
		// if the request body was buffered (and only the entire body, hence no body
		// set to read from after the buffer), make reading from the body idempotent
		// and reusable, so if a backend partially or fully reads the body but then
		// produces an error, the request can be repeated to the next backend with
		// the full body (retries should only happen for idempotent requests) (see #6259)
		if reqBodyBuf, ok := r.Body.(bodyReadCloser); ok && reqBodyBuf.body == nil {
			r.Body = io.NopCloser(bytes.NewReader(reqBodyBuf.buf.Bytes()))
		}

		var done bool
		done, proxyErr = h.proxyLoopIteration(clonedReq, r, w, proxyErr, start, retries, repl, reqHeader, reqHost, next)
		if done {
			break
		}
		if h.VerboseLogs {
			var lbWait time.Duration
			if h.LoadBalancing != nil {
				lbWait = time.Duration(h.LoadBalancing.TryInterval)
			}
			if c := h.logger.Check(zapcore.DebugLevel, "retrying"); c != nil {
				c.Write(zap.Error(proxyErr), zap.Duration("after", lbWait))
			}
		}
		retries++
	}

	// number of retries actually performed
	repl.Set("http.reverse_proxy.retries", retries)

	if proxyErr != nil {
		return statusError(proxyErr)
	}

	return nil
}

// proxyLoopIteration implements an iteration of the proxy loop. Despite the enormous amount of local state
// that has to be passed in, we brought this into its own method so that we could run defer more easily.
// It returns true when the loop is done and should break; false otherwise. The error value returned should
// be assigned to the proxyErr value for the next iteration of the loop (or the error handled after break).
func (h *Handler) proxyLoopIteration(r *http.Request, origReq *http.Request, w http.ResponseWriter, proxyErr error, start time.Time, retries int,
	repl *caddy.Replacer, reqHeader http.Header, reqHost string, next caddyhttp.Handler,
) (bool, error) {
	// get the updated list of upstreams
	upstreams := h.Upstreams
	if h.DynamicUpstreams != nil {
		dUpstreams, err := h.DynamicUpstreams.GetUpstreams(r)
		if err != nil {
			if c := h.logger.Check(zapcore.ErrorLevel, "failed getting dynamic upstreams; falling back to static upstreams"); c != nil {
				c.Write(zap.Error(err))
			}
		} else {
			upstreams = dUpstreams
			for _, dUp := range dUpstreams {
				h.provisionUpstream(dUp)
			}
			if c := h.logger.Check(zapcore.DebugLevel, "provisioned dynamic upstreams"); c != nil {
				c.Write(zap.Int("count", len(dUpstreams)))
			}
			defer func() {
				// these upstreams are dynamic, so they are only used for this iteration
				// of the proxy loop; be sure to let them go away when we're done with them
				for _, upstream := range dUpstreams {
					_, _ = hosts.Delete(upstream.String())
				}
			}()
		}
	}

	// choose an available upstream
	upstream := h.LoadBalancing.SelectionPolicy.Select(upstreams, r, w)
	if upstream == nil {
		/*
			如果没有选中（例如没有可用 upstream），构造 errNoUpstream（或保留上次错误），
			然后调用 tryAgain 判断是否继续等待/重试（基于 Retries / TryDuration / TryInterval / RetryMatch 等）
		*/
		if proxyErr == nil {
			proxyErr = caddyhttp.Error(http.StatusServiceUnavailable, errNoUpstream)
		}
		/*
			tryAgain 使用 start 时间和 retries 计数去判断是否耗时过多或次数达到上限，
			也会检查错误类型决定是否允许重试（例如拨号错误允许重试，但非拨号后产生的错误只有在满足 RetryMatch 的情况下才允许重试）。
		*/
		if !h.LoadBalancing.tryAgain(h.ctx, start, retries, proxyErr, r, h.logger) {
			return true, proxyErr
		}
		return false, proxyErr
	}

	// the dial address may vary per-request if placeholders are
	// used, so perform those replacements here; the resulting
	// DialInfo struct should have valid network address syntax
	/*
		此处会对 upstream 配置中使用的占位符进行替换（这也是为什么 prepareRequest 早先设置 replacer、并且在每次尝试前会设置 upstream.* 占位符的原因）
	*/
	dialInfo, err := upstream.fillDialInfo(repl)
	if err != nil {
		return true, fmt.Errorf("making dial info: %v", err)
	}

	if c := h.logger.Check(zapcore.DebugLevel, "selected upstream"); c != nil {
		c.Write(
			zap.String("dial", dialInfo.Address),
			zap.Int("total_upstreams", len(upstreams)),
		)
	}

	// attach to the request information about how to dial the upstream;
	// this is necessary because the information cannot be sufficiently
	// or satisfactorily represented in a URL
	caddyhttp.SetVar(r.Context(), dialInfoVarKey, dialInfo)

	// set placeholders with information about this upstream
	repl.Set("http.reverse_proxy.upstream.address", dialInfo.String())
	repl.Set("http.reverse_proxy.upstream.hostport", dialInfo.Address)
	repl.Set("http.reverse_proxy.upstream.host", dialInfo.Host)
	repl.Set("http.reverse_proxy.upstream.port", dialInfo.Port)
	repl.Set("http.reverse_proxy.upstream.requests", upstream.Host.NumRequests())
	repl.Set("http.reverse_proxy.upstream.max_requests", upstream.MaxRequests)
	repl.Set("http.reverse_proxy.upstream.fails", upstream.Host.Fails())

	// mutate request headers according to this upstream;
	// because we're in a retry loop, we have to copy
	// headers (and the r.Host value) from the original
	// so that each retry is identical to the first
	/*
		由于处于重试循环，必须保证每次尝试都是“从相同的初始请求状态”开始。reqHeader 和 reqHost 在 ServeHTTP 早前保存（它们是 prepareRequest 返回后的初始值，包含 rewrite、前端处理等结果）。

		这里新建 header map，然后把 reqHeader 的值拷贝进去（copyHeader 做逐键逐值的 Add），并把 Host 恢复为 reqHost。
		这样后续 ApplyToRequest（headers 模块）会在这个干净的起态上进行修改，而不会把之前尝试中对 r.Header 的改变累积到下一次尝试。
	*/
	if h.Headers != nil && h.Headers.Request != nil {
		r.Header = make(http.Header)
		copyHeader(r.Header, reqHeader)
		r.Host = reqHost
		h.Headers.Request.ApplyToRequest(r)
	}

	// proxy the request to that upstream
	/*
		调用 reverseProxy 来执行实际 roundtrip
	*/
	proxyErr = h.reverseProxy(w, r, origReq, repl, dialInfo, next)
	if proxyErr == nil || errors.Is(proxyErr, context.Canceled) {
		// context.Canceled happens when the downstream client
		// cancels the request, which is not our failure
		/*
			如果 reverseProxy 返回 nil：表示 roundtrip 和响应处理成功，函数返回 done=true, nil（整个 ServeHTTP 循环结束并视为成功）

			如果 error 是 context.Canceled（客户端取消连接），这里认为不是代理的失败（客户端已断开），也返回 done=true, nil（上游请求不可重试且客户端已断开，不应尝试重试）
		*/
		return true, nil
	}

	// if the roundtrip was successful, don't retry the request or
	// ding the health status of the upstream (an error can still
	// occur after the roundtrip if, for example, a response handler
	// after the roundtrip returns an error)
	/*
		reverseProxy 内部在某些情形（roundtrip 到 upstream 成功，但后续处理（例如 handle_response route）出错），会把该 route 错误包一层 roundtripSucceededError 返回。
		其含义：上游已经成功完成 roundtrip，不应重试（因为上游可能已接收请求）；但是上层需要把 route 错误当作最终应返回的错误。
	*/
	if succ, ok := proxyErr.(roundtripSucceededError); ok {
		return true, succ.error
	}

	/*
		countFailure 会将这次失败计入 upstream 的状态计数（passive health checks 相关），用于后续判断上游是否应该被标记为不健康并暂时从选择池中排除。
	*/
	// remember this failure (if enabled)
	h.countFailure(upstream)

	// if we've tried long enough, break
	if !h.LoadBalancing.tryAgain(h.ctx, start, retries, proxyErr, r, h.logger) {
		return true, proxyErr
	}

	return false, proxyErr
}

// Mapping of the canonical form of the headers, to the RFC 6455 form,
// i.e. `WebSocket` with uppercase 'S'.
var websocketHeaderMapping = map[string]string{
	"Sec-Websocket-Accept":     "Sec-WebSocket-Accept",
	"Sec-Websocket-Extensions": "Sec-WebSocket-Extensions",
	"Sec-Websocket-Key":        "Sec-WebSocket-Key",
	"Sec-Websocket-Protocol":   "Sec-WebSocket-Protocol",
	"Sec-Websocket-Version":    "Sec-WebSocket-Version",
}

// normalizeWebsocketHeaders ensures we use the standard casing as per
// RFC 6455, i.e. `WebSocket` with uppercase 'S'. Most servers don't
// care about this difference (read headers case insensitively), but
// some do, so this maximizes compatibility with upstreams.
// See https://github.com/caddyserver/caddy/pull/6621
func normalizeWebsocketHeaders(header http.Header) {
	for k, rk := range websocketHeaderMapping {
		if v, ok := header[k]; ok {
			delete(header, k)
			header[rk] = v
		}
	}
}

// prepareRequest clones req so that it can be safely modified without
// changing the original request or introducing data races. It then
// modifies it so that it is ready to be proxied, except for directing
// to a specific upstream. This method adjusts headers and other relevant
// properties of the cloned request and should be done just once (before
// proxying) regardless of proxy retries. This assumes that no mutations
// of the cloned request are performed by h during or after proxying.
/*
在把客户端请求代理到上游之前，做一次“安全的拷贝并预处理”——克隆请求并对该克隆做所有为上游准备的改动（重写、缓冲、头部清理、设置转发相关头等）。
它只做一次（在 ServeHTTP 的最开始被调用一次），之后代理循环（可能重试多个上游）会基于这个已准备好的克隆请求进行每次尝试。
*/
func (h Handler) prepareRequest(req *http.Request, repl *caddy.Replacer) (*http.Request, error) {
	req = cloneRequest(req)

	// if enabled, perform rewrites on the cloned request; if
	// the method is GET or HEAD, prevent the request body
	// from being copied to the upstream
	/*
		如果配置了 reverse_proxy.rewrite，会对克隆的请求应用 rewrite 规则（可能变更方法和 URI）
	*/
	if h.Rewrite != nil {
		changed := h.Rewrite.Rewrite(req, repl)
		if changed && (h.Rewrite.Method == "GET" || h.Rewrite.Method == "HEAD") {
			req.ContentLength = 0
			req.Body = nil
		}
	}

	// if enabled, buffer client request; this should only be
	// enabled if the upstream requires it and does not work
	// with "slow clients" (gunicorn, etc.) - this obviously
	// has a perf overhead and makes the proxy at risk of
	// exhausting memory and more susceptible to slowloris
	// attacks, so it is strongly recommended to only use this
	// feature if absolutely required, if read timeouts are
	// set, and if body size is limited
	/*
		bufferedBody 会把请求体读入缓冲（使用 bufPool），并返回一个 bodyReadCloser 包装，
		使后续可以在重试场景里重新从缓冲中读取完整 body（重要：如果要做跨上游重试，且需要将 body 重新发送，必须把 body 可重放）。
		如果缓冲完全读到 EOF，会设置 Content-Length 以便某些后端（如 fastcgi/php-fpm）能正确处理。
	*/
	if h.RequestBuffers != 0 && req.Body != nil {
		var readBytes int64
		req.Body, readBytes = h.bufferedBody(req.Body, h.RequestBuffers)
		// set Content-Length when body is fully buffered
		if b, ok := req.Body.(bodyReadCloser); ok && b.body == nil {
			req.ContentLength = readBytes
			req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		}
	}

	/*
		这是为了解决 Go 标准库中 transport 重试行为（参见注释中的 golang issue）。
		把 Body 设为 nil 能避免某些场景下 transport 无法重试或重复读取导致的问题。
	*/
	if req.ContentLength == 0 {
		req.Body = nil // Issue golang/go#16036: nil Body for http.Transport retries
	}

	/*
		关闭请求的 Connection 默认值（长连接）
	*/
	req.Close = false

	// if User-Agent is not set by client, then explicitly
	// disable it so it's not set to default value by std lib
	/*
		标准库如果没有 User-Agent 会插入默认值；这里显式设置为空，表示不想发送 User-Agent（除非客户端已提供）
	*/
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}

	// Indicate if request has been conveyed in early data.
	// RFC 8470: "An intermediary that forwards a request prior to the
	// completion of the TLS handshake with its client MUST send it with
	// the Early-Data header field set to “1” (i.e., it adds it if not
	// present in the request). An intermediary MUST use the Early-Data
	// header field if the request might have been subject to a replay and
	// might already have been forwarded by it or another instance
	// (see Section 6.2)."
	/*
		如果请求来自 TLS 且握手未完成（可能是早期数据/0-RTT），根据 RFC 8470 在转发时加 Early-Data: 1，表明该请求可能被重放/转发。
	*/
	if req.TLS != nil && !req.TLS.HandshakeComplete {
		req.Header.Set("Early-Data", "1")
	}

	/*
		检测到需要升级 websocket ，如需要会把 Connection: Upgrade 和 Upgrade: <type> 恢复到 header 中，
		并调用 normalizeWebsocketHeaders 将 Sec-Websocket-* 等首字母大小写规范化（由 RFC 6455 要求某些服务器对大小写敏感）。

		遍历 hopHeaders，删除 hop-by-hop 头（包括 Connection、Transfer-Encoding、Upgrade 等），并为 Te 特例保留 "trailers" token（如果客户端想要 trailer）。
	*/
	reqUpgradeType := upgradeType(req.Header)
	removeConnectionHeaders(req.Header)

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	// Issue golang/go#46313: don't skip if field is empty.
	for _, h := range hopHeaders {
		// Issue golang/go#21096: tell backend applications that care about trailer support
		// that we support trailers. (We do, but we don't go out of our way to
		// advertise that unless the incoming client request thought it was worth
		// mentioning.)
		if h == "Te" && httpguts.HeaderValuesContainsToken(req.Header["Te"], "trailers") {
			req.Header.Set("Te", "trailers")
			continue
		}
		req.Header.Del(h)
	}

	// After stripping all the hop-by-hop connection headers above, add back any
	// necessary for protocol upgrades, such as for websockets.
	if reqUpgradeType != "" {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", reqUpgradeType)
		normalizeWebsocketHeaders(req.Header)
	}

	// Set up the PROXY protocol info
	/*
		解析 address 为 netip.AddrPort；构造 ProxyProtocolInfo{AddrPort: addrPort} 并把它放入 req.Context
		目的：transport 层（例如 HTTPTransport 如果启用了 proxy_protocol）可能需要把客户端地址信息放入到上游的 Host 或者 PROXY protocol header 中；
		prepareRequest 在这里保存供下层使用。注意解析失败会尝试只解析地址（无端口）并继续。
	*/
	address := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey).(string)
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		// OK; probably didn't have a port
		addr, err := netip.ParseAddr(address)
		if err != nil {
			// Doesn't seem like a valid ip address at all
		} else {
			// Ok, only the port was missing
			addrPort = netip.AddrPortFrom(addr, 0)
		}
	}
	proxyProtocolInfo := ProxyProtocolInfo{AddrPort: addrPort}
	caddyhttp.SetVar(req.Context(), proxyProtocolInfoVarKey, proxyProtocolInfo)

	// some of the outbound requests require h1 (e.g. websocket)
	// https://github.com/golang/go/blob/4837fbe4145cd47b43eed66fee9eed9c2b988316/src/net/http/request.go#L1579
	if isWebsocket(req) {
		caddyhttp.SetVar(req.Context(), tlsH1OnlyVarKey, true)
	}

	// Add the supported X-Forwarded-* headers
	// 添加 X-Forwarded-* 系列头
	err = h.addForwardedHeaders(req)
	if err != nil {
		return nil, err
	}

	// Via header(s)
	req.Header.Add("Via", fmt.Sprintf("%d.%d Caddy", req.ProtoMajor, req.ProtoMinor))

	return req, nil
}

// addForwardedHeaders adds the de-facto standard X-Forwarded-*
// headers to the request before it is sent upstream.
//
// These headers are security sensitive, so care is taken to only
// use existing values for these headers from the incoming request
// if the client IP is trusted (i.e. coming from a trusted proxy
// sitting in front of this server). If the request didn't have
// the headers at all, then they will be added with the values
// that we can glean from the request.
func (h Handler) addForwardedHeaders(req *http.Request) error {
	// Parse the remote IP, ignore the error as non-fatal,
	// but the remote IP is required to continue, so we
	// just return early. This should probably never happen
	// though, unless some other module manipulated the request's
	// remote address and used an invalid value.
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// Remove the `X-Forwarded-*` headers to avoid upstreams
		// potentially trusting a header that came from the client
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-Host")
		return nil
	}

	// Client IP may contain a zone if IPv6, so we need
	// to pull that out before parsing the IP
	clientIP, _, _ = strings.Cut(clientIP, "%")
	ipAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return fmt.Errorf("invalid IP address: '%s': %v", clientIP, err)
	}

	// Check if the client is a trusted proxy
	trusted := caddyhttp.GetVar(req.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	for _, ipRange := range h.trustedProxies {
		if ipRange.Contains(ipAddr) {
			trusted = true
			break
		}
	}

	// If we aren't the first proxy, and the proxy is trusted,
	// retain prior X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	clientXFF := clientIP
	prior, ok, omit := allHeaderValues(req.Header, "X-Forwarded-For")
	if trusted && ok && prior != "" {
		clientXFF = prior + ", " + clientXFF
	}
	if !omit {
		req.Header.Set("X-Forwarded-For", clientXFF)
	}

	// Set X-Forwarded-Proto; many backend apps expect this,
	// so that they can properly craft URLs with the right
	// scheme to match the original request
	proto := "https"
	if req.TLS == nil {
		proto = "http"
	}
	prior, ok, omit = lastHeaderValue(req.Header, "X-Forwarded-Proto")
	if trusted && ok && prior != "" {
		proto = prior
	}
	if !omit {
		req.Header.Set("X-Forwarded-Proto", proto)
	}

	// Set X-Forwarded-Host; often this is redundant because
	// we pass through the request Host as-is, but in situations
	// where we proxy over HTTPS, the user may need to override
	// Host themselves, so it's helpful to send the original too.
	host := req.Host
	prior, ok, omit = lastHeaderValue(req.Header, "X-Forwarded-Host")
	if trusted && ok && prior != "" {
		host = prior
	}
	if !omit {
		req.Header.Set("X-Forwarded-Host", host)
	}

	return nil
}

// reverseProxy performs a round-trip to the given backend and processes the response with the client.
// (This method is mostly the beginning of what was borrowed from the net/http/httputil package in the
// Go standard library which was used as the foundation.)
func (h *Handler) reverseProxy(rw http.ResponseWriter, req *http.Request, origReq *http.Request, repl *caddy.Replacer, di DialInfo, next caddyhttp.Handler) error {
	_ = di.Upstream.Host.countRequest(1)
	//nolint:errcheck
	defer di.Upstream.Host.countRequest(-1)

	// point the request to this upstream
	/*
		把 req.URL.Host 设置为 di.Address（或 di.Host），并在需要时把客户端地址信息附加到 Host（用于自定义 transport 区分不同客户端、proxy_protocol 情形）。
		重要：directRequest 只修改 URL（保证请求其它字段不被非必要改变），拨号细节（network, SNI 等）由 transport 通过从上下文读取 di 处理。
	*/
	h.directRequest(req, di)

	server := req.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	shouldLogCredentials := server.Logs != nil && server.Logs.ShouldLogCredentials

	// Forward 1xx status codes, backported from https://github.com/golang/go/pull/53164
	var (
		roundTripMutex sync.Mutex
		roundTripDone  bool
	)
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			roundTripMutex.Lock()
			defer roundTripMutex.Unlock()
			if roundTripDone {
				// If RoundTrip has returned, don't try to further modify
				// the ResponseWriter's header map.
				return nil
			}
			h := rw.Header()
			copyHeader(h, http.Header(header))
			rw.WriteHeader(code)

			// Clear headers coming from the backend
			// (it's not automatically done by ResponseWriter.WriteHeader() for 1xx responses)
			clear(h)

			return nil
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// do the round-trip
	start := time.Now()
	res, err := h.Transport.RoundTrip(req)
	duration := time.Since(start)

	// record that the round trip is done for the 1xx response handler
	roundTripMutex.Lock()
	roundTripDone = true
	roundTripMutex.Unlock()

	// emit debug log with values we know are safe,
	// or if there is no error, emit fuller log entry
	logger := h.logger.With(
		zap.String("upstream", di.Upstream.String()),
		zap.Duration("duration", duration),
		zap.Object("request", caddyhttp.LoggableHTTPRequest{
			Request:              req,
			ShouldLogCredentials: shouldLogCredentials,
		}),
	)

	const logMessage = "upstream roundtrip"

	if err != nil {
		if c := logger.Check(zapcore.DebugLevel, logMessage); c != nil {
			c.Write(zap.Error(err))
		}
		return err
	}
	if c := logger.Check(zapcore.DebugLevel, logMessage); c != nil {
		c.Write(
			zap.Object("headers", caddyhttp.LoggableHTTPHeader{
				Header:               res.Header,
				ShouldLogCredentials: shouldLogCredentials,
			}),
			zap.Int("status", res.StatusCode),
		)
	}

	// duration until upstream wrote response headers (roundtrip duration)
	repl.Set("http.reverse_proxy.upstream.latency", duration)
	repl.Set("http.reverse_proxy.upstream.latency_ms", duration.Seconds()*1e3) // multiply seconds to preserve decimal (see #4666)

	// update circuit breaker on current conditions
	/*
		如果 upstream 绑定了 circuit breaker，则把这次 roundtrip 的状态码与 latency 汇报给 CB，CB 可能基于策略打开/关闭。
	*/
	if di.Upstream.cb != nil {
		di.Upstream.cb.RecordMetric(res.StatusCode, duration)
	}

	// perform passive health checks (if enabled)
	/*
		被动健康检查配置
		若返回状态码匹配被认为“不健康”的模式，就对该 upstream 增加一次 failure（h.countFailure 会更新 upstream.Host 的失败计数、可能触发下线）。
		若响应延迟超过阈值，也计一次 failure。
	*/
	if h.HealthChecks != nil && h.HealthChecks.Passive != nil {
		// strike if the status code matches one that is "bad"
		for _, badStatus := range h.HealthChecks.Passive.UnhealthyStatus {
			if caddyhttp.StatusCodeMatches(res.StatusCode, badStatus) {
				h.countFailure(di.Upstream)
			}
		}

		// strike if the roundtrip took too long
		if h.HealthChecks.Passive.UnhealthyLatency > 0 &&
			duration >= time.Duration(h.HealthChecks.Passive.UnhealthyLatency) {
			h.countFailure(di.Upstream)
		}
	}

	// if enabled, buffer the response body
	/*
		如果配置了 response buffering，会把上游的响应 body 读入缓冲并用 bodyReadCloser 包装，便于后续处理（例如 handle_response 里可能要 copy_response）。
		bufferedBody 使用 bufPool 减少分配，但注意缓冲会增加内存消耗，配置须谨慎。
	*/
	if h.ResponseBuffers != 0 {
		res.Body, _ = h.bufferedBody(res.Body, h.ResponseBuffers)
	}

	// see if any response handler is configured for this response from the backend
	for i, rh := range h.HandleResponse {
		if rh.Match != nil && !rh.Match.Match(res.StatusCode, res.Header) {
			continue
		}

		// if configured to only change the status code,
		// do that then continue regular proxy response
		if statusCodeStr := rh.StatusCode.String(); statusCodeStr != "" {
			statusCode, err := strconv.Atoi(repl.ReplaceAll(statusCodeStr, ""))
			if err != nil {
				return caddyhttp.Error(http.StatusInternalServerError, err)
			}
			if statusCode != 0 {
				res.StatusCode = statusCode
			}
			break
		}

		// set up the replacer so that parts of the original response can be
		// used for routing decisions
		for field, value := range res.Header {
			repl.Set("http.reverse_proxy.header."+field, strings.Join(value, ","))
		}
		repl.Set("http.reverse_proxy.status_code", res.StatusCode)
		repl.Set("http.reverse_proxy.status_text", res.Status)

		if c := logger.Check(zapcore.DebugLevel, "handling response"); c != nil {
			c.Write(zap.Int("handler", i))
		}

		// we make some data available via request context to child routes
		// so that they may inherit some options and functions from the
		// handler, and be able to copy the response.
		// we use the original request here, so that any routes from 'next'
		// see the original request rather than the proxy cloned request.
		hrc := &handleResponseContext{
			handler:  h,
			response: res,
			start:    start,
			logger:   logger,
		}
		ctx := origReq.Context()
		ctx = context.WithValue(ctx, proxyHandleResponseContextCtxKey, hrc)

		// pass the request through the response handler routes
		routeErr := rh.Routes.Compile(next).ServeHTTP(rw, origReq.WithContext(ctx))

		// close the response body afterwards, since we don't need it anymore;
		// either a route had 'copy_response' which already consumed the body,
		// or some other terminal handler ran which doesn't need the response
		// body after that point (e.g. 'file_server' for X-Accel-Redirect flow),
		// or we fell through to subsequent handlers past this proxy
		// (e.g. forward auth's 2xx response flow).
		if !hrc.isFinalized {
			res.Body.Close()
		}

		// wrap any route error in roundtripSucceededError so caller knows that
		// the roundtrip was successful and to not retry
		if routeErr != nil {
			return roundtripSucceededError{routeErr}
		}

		// we're done handling the response, and we don't want to
		// fall through to the default finalize/copy behaviour
		return nil
	}

	// copy the response body and headers back to the upstream client
	return h.finalizeResponse(rw, req, res, repl, start, logger)
}

// finalizeResponse prepares and copies the response.
func (h *Handler) finalizeResponse(
	rw http.ResponseWriter,
	req *http.Request,
	res *http.Response,
	repl *caddy.Replacer,
	start time.Time,
	logger *zap.Logger,
) error {
	// deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	/*
		当上游返回 101（例如 WebSocket、h2c 的升级）时，不能用常规的拷贝逻辑，要进行连接升级处理（通常需要 hijack 或建立双向字节流转发）。
		finalizeResponse 将请求交给 handleUpgradeResponse 来做升级隧道的建立与双向拷贝，然后等待（wg.Wait）直到升级处理完成，返回 nil 表示已成功处理升级路径。
	*/
	if res.StatusCode == http.StatusSwitchingProtocols {
		var wg sync.WaitGroup
		h.handleUpgradeResponse(logger, &wg, rw, req, res)
		wg.Wait()
		return nil
	}

	removeConnectionHeaders(res.Header)

	for _, h := range hopHeaders {
		res.Header.Del(h)
	}

	// delete our Server header and use Via instead (see #6275)
	rw.Header().Del("Server")
	var protoPrefix string
	if !strings.HasPrefix(strings.ToUpper(res.Proto), "HTTP/") {
		protoPrefix = res.Proto[:strings.Index(res.Proto, "/")+1]
	}
	rw.Header().Add("Via", fmt.Sprintf("%s%d.%d Caddy", protoPrefix, res.ProtoMajor, res.ProtoMinor))

	// apply any response header operations
	/*
		如果用户在 reverse_proxy 配置中设置了 response header 操作（例如添加、删除、替换 header），在将 header 发回客户端之前会在这里应用。
		Require 用来限制仅在某些状态码或 header 条件下应用这些操作。ApplyTo 能使用 replacer（repl）中的占位符（例如 upstream.*）进行动态替换。
	*/
	if h.Headers != nil && h.Headers.Response != nil {
		if h.Headers.Response.Require == nil ||
			h.Headers.Response.Require.Match(res.StatusCode, res.Header) {
			h.Headers.Response.ApplyTo(res.Header, repl)
		}
	}

	copyHeader(rw.Header(), res.Header)

	// The "Trailer" header isn't included in the Transport's response,
	// at least for *http.Transport. Build it up from Trailer.
	/*
		标准库的 Transport（至少 *http.Transport）通常不会把 Trailer header 放回 res.Header 里，而是放在 res.Trailer map。
		要让客户端知道会发送哪些 trailer（告知要使用 chunked 编码并在结束后发送 trailer），代理必须在响应头里添加 "Trailer": "<keys>"。
		这一步就是从 res.Trailer 的 map 构建 Trailer 报头。
	*/
	announcedTrailers := len(res.Trailer)
	if announcedTrailers > 0 {
		trailerKeys := make([]string, 0, len(res.Trailer))
		for k := range res.Trailer {
			trailerKeys = append(trailerKeys, k)
		}
		rw.Header().Add("Trailer", strings.Join(trailerKeys, ", "))
	}

	rw.WriteHeader(res.StatusCode)
	if h.VerboseLogs {
		logger.Debug("wrote header")
	}

	err := h.copyResponse(rw, res.Body, h.flushInterval(req, res), logger)
	errClose := res.Body.Close() // close now, instead of defer, to populate res.Trailer
	if h.VerboseLogs || errClose != nil {
		if c := logger.Check(zapcore.DebugLevel, "closed response body from upstream"); c != nil {
			c.Write(zap.Error(errClose))
		}
	}
	if err != nil {
		// we're streaming the response and we've already written headers, so
		// there's nothing an error handler can do to recover at this point;
		// we'll just log the error and abort the stream here and panic just as
		// the standard lib's proxy to propagate the stream error.
		// see issue https://github.com/caddyserver/caddy/issues/5951
		if c := logger.Check(zapcore.WarnLevel, "aborting with incomplete response"); c != nil {
			c.Write(zap.Error(err))
		}
		// no extra logging from stdlib
		panic(http.ErrAbortHandler)
	}

	/*
		因为不同 Transport 对 Trailer 的支持和填充时机不一致（有时在 res.Body.Close() 后填充），
		代理必须在复制 body 前公告 Trailer 键，并在 body 复制结束后把实际 trailers 写回或作为 Trailer- 前缀添加到头部。
	*/
	if len(res.Trailer) > 0 {
		// Force chunking if we saw a response trailer.
		// This prevents net/http from calculating the length for short
		// bodies and adding a Content-Length.
		//nolint:bodyclose
		http.NewResponseController(rw).Flush()
	}

	// total duration spent proxying, including writing response body
	repl.Set("http.reverse_proxy.upstream.duration", time.Since(start))
	repl.Set("http.reverse_proxy.upstream.duration_ms", time.Since(start).Seconds()*1e3)

	if len(res.Trailer) == announcedTrailers {
		copyHeader(rw.Header(), res.Trailer)
		return nil
	}

	for k, vv := range res.Trailer {
		k = http.TrailerPrefix + k
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}

	if h.VerboseLogs {
		logger.Debug("response finalized")
	}

	return nil
}

// tryAgain takes the time that the handler was initially invoked,
// the amount of retries already performed, as well as any error
// currently obtained, and the request being tried, and returns
// true if another attempt should be made at proxying the request.
// If true is returned, it has already blocked long enough before
// the next retry (i.e. no more sleeping is needed). If false is
// returned, the handler should stop trying to proxy the request.
func (lb LoadBalancing) tryAgain(ctx caddy.Context, start time.Time, retries int, proxyErr error, req *http.Request, logger *zap.Logger) bool {
	// no retries are configured
	if lb.TryDuration == 0 && lb.Retries == 0 {
		return false
	}

	// if we've tried long enough, break
	if lb.TryDuration > 0 && time.Since(start) >= time.Duration(lb.TryDuration) {
		return false
	}

	// if we've reached the retry limit, break
	if lb.Retries > 0 && retries >= lb.Retries {
		return false
	}

	// if the error occurred while dialing (i.e. a connection
	// could not even be established to the upstream), then it
	// should be safe to retry, since without a connection, no
	// HTTP request can be transmitted; but if the error is not
	// specifically a dialer error, we need to be careful
	if proxyErr != nil {
		_, isDialError := proxyErr.(DialError)
		herr, isHandlerError := proxyErr.(caddyhttp.HandlerError)

		// if the error occurred after a connection was established,
		// we have to assume the upstream received the request, and
		// retries need to be carefully decided, because some requests
		// are not idempotent
		if !isDialError && (!isHandlerError || !errors.Is(herr, errNoUpstream)) {
			if lb.RetryMatch == nil && req.Method != "GET" {
				// by default, don't retry requests if they aren't GET
				return false
			}

			match, err := lb.RetryMatch.AnyMatchWithError(req)
			if err != nil {
				logger.Error("error matching request for retry", zap.Error(err))
				return false
			}
			if !match {
				return false
			}
		}
	}

	// fast path; if the interval is zero, we don't need to wait
	if lb.TryInterval == 0 {
		return true
	}

	// otherwise, wait and try the next available host
	timer := time.NewTimer(time.Duration(lb.TryInterval))
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		if !timer.Stop() {
			// if the timer has been stopped then read from the channel
			<-timer.C
		}
		return false
	}
}

// directRequest modifies only req.URL so that it points to the upstream
// in the given DialInfo. It must modify ONLY the request URL.
func (h *Handler) directRequest(req *http.Request, di DialInfo) {
	// we need a host, so set the upstream's host address
	reqHost := di.Address

	// if the port equates to the scheme, strip the port because
	// it's weird to make a request like http://example.com:80/.
	if (req.URL.Scheme == "http" && di.Port == "80") ||
		(req.URL.Scheme == "https" && di.Port == "443") {
		reqHost = di.Host
	}

	// add client address to the host to let transport differentiate requests from different clients
	if ht, ok := h.Transport.(*HTTPTransport); ok && ht.ProxyProtocol != "" {
		if proxyProtocolInfo, ok := caddyhttp.GetVar(req.Context(), proxyProtocolInfoVarKey).(ProxyProtocolInfo); ok {
			reqHost = proxyProtocolInfo.AddrPort.String() + "->" + reqHost
		}
	}

	req.URL.Host = reqHost
}

func (h Handler) provisionUpstream(upstream *Upstream) {
	// create or get the host representation for this upstream
	upstream.fillHost()

	// give it the circuit breaker, if any
	upstream.cb = h.CB

	// if the passive health checker has a non-zero UnhealthyRequestCount
	// but the upstream has no MaxRequests set (they are the same thing,
	// but the passive health checker is a default value for upstreams
	// without MaxRequests), copy the value into this upstream, since the
	// value in the upstream (MaxRequests) is what is used during
	// availability checks
	if h.HealthChecks != nil &&
		h.HealthChecks.Passive != nil &&
		h.HealthChecks.Passive.UnhealthyRequestCount > 0 &&
		upstream.MaxRequests == 0 {
		upstream.MaxRequests = h.HealthChecks.Passive.UnhealthyRequestCount
	}

	// upstreams need independent access to the passive
	// health check policy because passive health checks
	// run without access to h.
	if h.HealthChecks != nil {
		upstream.healthCheckPolicy = h.HealthChecks.Passive
	}
}

// bufferedBody reads originalBody into a buffer with maximum size of limit (-1 for unlimited),
// then returns a reader for the buffer along with how many bytes were buffered. Always close
// the return value when done with it, just like if it was the original body! If limit is 0
// (which it shouldn't be), this function returns its input; i.e. is a no-op, for safety.
// Otherwise, it returns bodyReadCloser, the original body will be closed and body will be nil
// if it's explicitly configured to buffer all or EOF is reached when reading.
// TODO: the error during reading is discarded if the limit is negative, should the error be propagated
// to upstream/downstream?
func (h Handler) bufferedBody(originalBody io.ReadCloser, limit int64) (io.ReadCloser, int64) {
	if limit == 0 {
		return originalBody, 0
	}
	var written int64
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if limit > 0 {
		var err error
		written, err = io.CopyN(buf, originalBody, limit)
		if (err != nil && err != io.EOF) || written == limit {
			return bodyReadCloser{
				Reader: io.MultiReader(buf, originalBody),
				buf:    buf,
				body:   originalBody,
			}, written
		}
	} else {
		written, _ = io.Copy(buf, originalBody)
	}
	originalBody.Close() // no point in keeping it open
	return bodyReadCloser{
		Reader: buf,
		buf:    buf,
	}, written
}

// cloneRequest makes a semi-deep clone of origReq.
//
// Most of this code is borrowed from the Go stdlib reverse proxy,
// but we make a shallow-ish clone the request (deep clone only
// the headers and URL) so we can avoid manipulating the original
// request when using it to proxy upstream. This prevents request
// corruption and data races.
/*
拷贝最外层 http.Request 结构体，深拷贝 Header、Trailer、URL（并清空 URL.Scheme 和 URL.Host，避免把客户端请求行里的绝对 URL 覆盖代理的决策）
目的是避免修改原始请求，防止并发修改或后续处理看到受污染的请求。
*/
func cloneRequest(origReq *http.Request) *http.Request {
	req := new(http.Request)
	*req = *origReq
	if origReq.URL != nil {
		newURL := new(url.URL)
		*newURL = *origReq.URL
		if origReq.URL.User != nil {
			newURL.User = new(url.Userinfo)
			*newURL.User = *origReq.URL.User
		}
		// sanitize the request URL; we expect it to not contain the
		// scheme and host since those should be determined by r.TLS
		// and r.Host respectively, but some clients may include it
		// in the request-line, which is technically valid in HTTP,
		// but breaks reverseproxy behaviour, overriding how the
		// dialer will behave. See #4237 for context.
		newURL.Scheme = ""
		newURL.Host = ""
		req.URL = newURL
	}
	if origReq.Header != nil {
		req.Header = origReq.Header.Clone()
	}
	if origReq.Trailer != nil {
		req.Trailer = origReq.Trailer.Clone()
	}
	return req
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// allHeaderValues gets all values for a given header field,
// joined by a comma and space if more than one is set. If the
// header field is nil, then the omit is true, meaning some
// earlier logic in the server wanted to prevent this header from
// getting written at all. If the header is empty, then ok is
// false. Callers should still check that the value is not empty
// (the header field may be set but have an empty value).
func allHeaderValues(h http.Header, field string) (value string, ok bool, omit bool) {
	values, ok := h[http.CanonicalHeaderKey(field)]
	if ok && values == nil {
		return "", true, true
	}
	if len(values) == 0 {
		return "", false, false
	}
	return strings.Join(values, ", "), true, false
}

// lastHeaderValue gets the last value for a given header field
// if more than one is set. If the header field is nil, then
// the omit is true, meaning some earlier logic in the server
// wanted to prevent this header from getting written at all.
// If the header is empty, then ok is false. Callers should
// still check that the value is not empty (the header field
// may be set but have an empty value).
func lastHeaderValue(h http.Header, field string) (value string, ok bool, omit bool) {
	values, ok := h[http.CanonicalHeaderKey(field)]
	if ok && values == nil {
		return "", true, true
	}
	if len(values) == 0 {
		return "", false, false
	}
	return values[len(values)-1], true, false
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

// removeConnectionHeaders removes hop-by-hop headers listed in the "Connection" header of h.
// See RFC 7230, section 6.1
func removeConnectionHeaders(h http.Header) {
	for _, f := range h["Connection"] {
		for sf := range strings.SplitSeq(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}

// statusError returns an error value that has a status code.
func statusError(err error) error {
	// errors proxying usually mean there is a problem with the upstream(s)
	statusCode := http.StatusBadGateway

	// timeout errors have a standard status code (see issue #4823)
	if err, ok := err.(net.Error); ok && err.Timeout() {
		statusCode = http.StatusGatewayTimeout
	}

	// if the client canceled the request (usually this means they closed
	// the connection, so they won't see any response), we can report it
	// as a client error (4xx) and not a server error (5xx); unfortunately
	// the Go standard library, at least at time of writing in late 2020,
	// obnoxiously wraps the exported, standard context.Canceled error with
	// an unexported garbage value that we have to do a substring check for:
	// https://github.com/golang/go/blob/6965b01ea248cabb70c3749fd218b36089a21efb/src/net/net.go#L416-L430
	if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "operation was canceled") {
		// regrettably, there is no standard error code for "client closed connection", but
		// for historical reasons we can use a code that a lot of people are already using;
		// using 5xx is problematic for users; see #3748
		statusCode = 499
	}
	return caddyhttp.Error(statusCode, err)
}

// LoadBalancing has parameters related to load balancing.
type LoadBalancing struct {
	// A selection policy is how to choose an available backend.
	// The default policy is random selection.
	SelectionPolicyRaw json.RawMessage `json:"selection_policy,omitempty" caddy:"namespace=http.reverse_proxy.selection_policies inline_key=policy"`

	// How many times to retry selecting available backends for each
	// request if the next available host is down. If try_duration is
	// also configured, then retries may stop early if the duration
	// is reached. By default, retries are disabled (zero).
	Retries int `json:"retries,omitempty"`

	// How long to try selecting available backends for each request
	// if the next available host is down. Clients will wait for up
	// to this long while the load balancer tries to find an available
	// upstream host. If retries is also configured, tries may stop
	// early if the maximum retries is reached. By default, retries
	// are disabled (zero duration).
	TryDuration caddy.Duration `json:"try_duration,omitempty"`

	// How long to wait between selecting the next host from the pool.
	// Default is 250ms if try_duration is enabled, otherwise zero. Only
	// relevant when a request to an upstream host fails. Be aware that
	// setting this to 0 with a non-zero try_duration can cause the CPU
	// to spin if all backends are down and latency is very low.
	TryInterval caddy.Duration `json:"try_interval,omitempty"`

	// A list of matcher sets that restricts with which requests retries are
	// allowed. A request must match any of the given matcher sets in order
	// to be retried if the connection to the upstream succeeded but the
	// subsequent round-trip failed. If the connection to the upstream failed,
	// a retry is always allowed. If unspecified, only GET requests will be
	// allowed to be retried. Note that a retry is done with the next available
	// host according to the load balancing policy.
	RetryMatchRaw caddyhttp.RawMatcherSets `json:"retry_match,omitempty" caddy:"namespace=http.matchers"`

	SelectionPolicy Selector              `json:"-"`
	RetryMatch      caddyhttp.MatcherSets `json:"-"`
}

// Selector selects an available upstream from the pool.
type Selector interface {
	Select(UpstreamPool, *http.Request, http.ResponseWriter) *Upstream
}

// UpstreamSource gets the list of upstreams that can be used when
// proxying a request. Returned upstreams will be load balanced and
// health-checked. This should be a very fast function -- instant
// if possible -- and the return value must be as stable as possible.
// In other words, the list of upstreams should ideally not change much
// across successive calls. If the list of upstreams changes or the
// ordering is not stable, load balancing will suffer. This function
// may be called during each retry, multiple times per request, and as
// such, needs to be instantaneous. The returned slice will not be
// modified.
type UpstreamSource interface {
	GetUpstreams(*http.Request) ([]*Upstream, error)
}

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Alt-Svc",
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

// DialError is an error that specifically occurs
// in a call to Dial or DialContext.
type DialError struct{ error }

// TLSTransport is implemented by transports
// that are capable of using TLS.
type TLSTransport interface {
	// TLSEnabled returns true if the transport
	// has TLS enabled, false otherwise.
	TLSEnabled() bool

	// EnableTLS enables TLS within the transport
	// if it is not already, using the provided
	// value as a basis for the TLS config.
	EnableTLS(base *TLSConfig) error
}

// roundtripSucceededError is an error type that is returned if the
// roundtrip succeeded, but an error occurred after-the-fact.
type roundtripSucceededError struct{ error }

// bodyReadCloser is a reader that, upon closing, will return
// its buffer to the pool and close the underlying body reader.
type bodyReadCloser struct {
	io.Reader
	buf  *bytes.Buffer
	body io.ReadCloser
}

func (brc bodyReadCloser) Close() error {
	bufPool.Put(brc.buf)
	if brc.body != nil {
		return brc.body.Close()
	}
	return nil
}

// bufPool is used for buffering requests and responses.
var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// handleResponseContext carries some contextual information about the
// current proxy handling.
type handleResponseContext struct {
	// handler is the active proxy handler instance, so that
	// routes like copy_response may inherit some config
	// options and have access to handler methods.
	handler *Handler

	// response is the actual response received from the proxy
	// roundtrip, to potentially be copied if a copy_response
	// handler is in the handle_response routes.
	response *http.Response

	// start is the time just before the proxy roundtrip was
	// performed, used for logging.
	start time.Time

	// logger is the prepared logger which is used to write logs
	// with the request, duration, and selected upstream attached.
	logger *zap.Logger

	// isFinalized is whether the response has been finalized,
	// i.e. copied and closed, to make sure that it doesn't
	// happen twice.
	isFinalized bool
}

// proxyHandleResponseContextCtxKey is the context key for the active proxy handler
// so that handle_response routes can inherit some config options
// from the proxy handler.
const proxyHandleResponseContextCtxKey caddy.CtxKey = "reverse_proxy_handle_response_context"

// errNoUpstream occurs when there are no upstream available.
var errNoUpstream = fmt.Errorf("no upstreams available")

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
