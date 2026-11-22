package core

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	delayTestConcurrency    = 50
	defaultTestURL          = "https://www.gstatic.com/generate_204"
	defaultDelayTestTimeout = 5 * time.Second

	googleStatusUnknown int32 = 0
	googleStatusNative  int32 = 1
	googleStatusHK      int32 = 2

	googleCheckURL = "https://www.google.com/"
	googleHKHost   = "google.com.hk"
)

var errGoogleRedirectHK = errors.New("google redirected to hk")

var (
	delayTestSlots     = make(slots, delayTestConcurrency)
	anyDelayTestStatus utils.IntRanges[uint16]

	testURL                 atomic.Pointer[string]
	missingDelayTestProxyAt atomic.Int64
)

func setTestURL(url string) {
	if url == "" {
		return
	}
	constant.DefaultTestURL = url
	testURL.Store(&url)
}

func currentTestURL() string {
	if url := testURL.Load(); url != nil && *url != "" {
		return *url
	}
	return defaultTestURL
}

const (
	delayTimedOut int32 = -1
	delayFailed   int32 = -2
)

func delayValue(delay uint16, timedOut bool) int32 {
	switch {
	case delay > 0:
		return int32(delay)
	case timedOut:
		return delayTimedOut
	default:
		return delayFailed
	}
}

// A name the tunnel does not know is what an apply that fell back to the
// default config looks like: every node of the profile fails its test. Say so
// once a second, not once per node, so the log names the real failure.
func reportMissingDelayTestProxy(name string) {
	now := time.Now().UnixNano()
	last := missingDelayTestProxyAt.Load()
	if last != 0 && now-last < int64(time.Second) {
		return
	}
	if !missingDelayTestProxyAt.CompareAndSwap(last, now) {
		return
	}
	logError("delay test: %q is not part of the applied config", name)
}

// A nil answer means the test never got a slot, which says nothing about the proxy.
func handleTestDelay(params *TestDelayParams) *Delay {
	url := params.TestUrl
	if url == "" {
		url = currentTestURL()
	}
	result := &Delay{Name: params.ProxyName, Url: url, Value: delayFailed}

	proxy := lookupProxy(params.ProxyName)
	if proxy == nil {
		reportMissingDelayTestProxy(params.ProxyName)
		return result
	}

	timeout, configured := configuredTestTimeout(proxy.Name(), url)
	if !configured {
		timeout = timeoutFromMillis(params.Timeout, defaultDelayTestTimeout)
	}
	if !delayTestSlots.acquireWithin(context.Background(), timeout) {
		return nil
	}
	defer delayTestSlots.release()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	googleCtx, cancelGoogle := context.WithCancel(ctx)
	defer cancelGoogle()
	googleCh := make(chan int32, 1)
	go func() {
		googleCh <- checkGoogleRedirect(googleCtx, proxy)
	}()

	delay, err := proxy.URLTest(ctx, url, anyDelayTestStatus)
	if err != nil {
		delay = 0
	}
	result.Value = delayValue(delay, ctx.Err() != nil)
	if result.Value > 0 {
		result.GoogleStatus = <-googleCh
	} else {
		cancelGoogle()
	}
	return result
}

func isGoogleHKHost(host string) bool {
	lower := strings.ToLower(host)
	return lower == googleHKHost || strings.HasSuffix(lower, "."+googleHKHost)
}

func checkGoogleRedirect(ctx context.Context, proxy constant.Proxy) int32 {
	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return googleStatusUnknown
	}
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
			metadata, err := probeMetadata(address)
			if err != nil {
				return nil, err
			}
			return proxy.DialContext(dialCtx, metadata)
		},
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
		MaxIdleConns:        1,
		TLSHandshakeTimeout: defaultDelayTestTimeout,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if isGoogleHKHost(req.URL.Hostname()) {
				return errGoogleRedirectHK
			}
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleCheckURL, nil)
	if err != nil {
		return googleStatusUnknown
	}
	req.Header.Set("User-Agent", browserUserAgent)
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errGoogleRedirectHK) {
			return googleStatusHK
		}
		return googleStatusUnknown
	}
	_ = resp.Body.Close()

	if resp.Request != nil && isGoogleHKHost(resp.Request.URL.Hostname()) {
		return googleStatusHK
	}
	if loc := resp.Header.Get("Location"); loc != "" && strings.Contains(strings.ToLower(loc), googleHKHost) {
		return googleStatusHK
	}
	return googleStatusNative
}

type testTimeoutProvider interface {
	TestTimeout(url string) (time.Duration, bool)
}

// The longest stands, so no scheduled check passes a node the manual test fails.
func configuredTestTimeout(name, url string) (time.Duration, bool) {
	var longest time.Duration
	for _, pd := range tunnel.ProvidersSnapshot() {
		timed, ok := pd.(testTimeoutProvider)
		if !ok {
			continue
		}
		timeout, ok := timed.TestTimeout(url)
		if !ok || timeout <= longest {
			continue
		}
		if slices.ContainsFunc(pd.Proxies(), func(p constant.Proxy) bool { return p.Name() == name }) {
			longest = timeout
		}
	}
	return longest, longest > 0
}
