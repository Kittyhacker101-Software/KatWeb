// KatWeb by kittyhacker101 - HTTP(S) / Websockets Reverse Proxy
package main

import (
	"crypto/tls"
	"github.com/yhat/wsutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	// tlsc is a TLS configuration optimized for speed, instead of security
	tlsp = &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	proxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			prox := conf.Proxy[GetProxy(r)]
			r.URL, _ = url.Parse(prox.URL + strings.TrimPrefix(r.URL.String(), "/"+prox.Loc))
		},
		Transport: &http.Transport{
			TLSClientConfig:     tlsp,
			MaxIdleConns:        512,
			MaxIdleConnsPerHost: 512,
			IdleConnTimeout:     time.Duration(conf.DatTime*8) * time.Second,
			DisableCompression:  true,
		},
	}

	wsproxy = &wsutil.ReverseProxy{
		Director: func(r *http.Request) {
			prox := conf.Proxy[GetProxy(r)]
			r.URL, _ = url.Parse(prox.URL + strings.TrimPrefix(r.URL.String(), "/"+prox.Loc))
			if r.URL.Scheme == "https" {
				r.URL.Scheme = "wss://"
			} else {
				r.URL.Scheme = "ws://"
			}
		},
		TLSClientConfig: tlsp,
	}
)

// GetProxy finds the correct proxy index to use from the conf.Proxy struct
func GetProxy(r *http.Request) int {
	url, err := url.QueryUnescape(r.URL.EscapedPath())
	if err != nil {
		url = r.URL.EscapedPath()
	}

	for i := range conf.Proxy {
		if strings.HasPrefix(url, "/"+conf.Proxy[i].Loc) || r.Host == conf.Proxy[i].Loc {
			return i
		}
	}

	return -1
}
