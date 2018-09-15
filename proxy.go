// KatWeb by kittyhacker101 - HTTP(S) / Websockets Reverse Proxy
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yhat/wsutil"
)

// UpdateData contains a struct for parsing returned json from the request
type UpdateData struct {
	Latest string `json:"tag_name"`
}

var (
	tlsp = &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: true,
	}

	proxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			prox, loc := GetProxy(r)
			u, err := url.Parse(prox + strings.TrimPrefix(r.URL.String(), "/"+loc))
			if err == nil {
				r.URL = u
				return
			}
			r.URL = fixProxy(r.URL, loc)
			r.Host = r.URL.Host
		},
		ErrorLog: Logger,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tlsp,
			MaxIdleConns:        4096,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     time.Duration(conf.DatTime*8) * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			StyledError(w, "502 Bad Gateway", "The server was acting as a proxy and received an invalid response from the upstream server.", http.StatusBadGateway)
		},
	}

	wsproxy = &wsutil.ReverseProxy{
		Director: func(r *http.Request) {
			prox, loc := GetProxy(r)
			u, err := url.Parse(prox + strings.TrimPrefix(r.URL.String(), "/"+loc))
			if err != nil {
				r.URL = fixProxy(r.URL, loc)
				return
			}

			if r.URL.Scheme == "https" {
				u.Scheme = "wss://"
			} else {
				u.Scheme = "ws://"
			}

			r.URL = u
		},
		ErrorLog:        Logger,
		TLSClientConfig: tlsp,
	}

	// updateClient is the http.Client used for checking the latest version of KatWeb
	updateClient = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   tlsp,
		},
		Timeout: 2 * time.Second,
	}

	proxyMap, redirMap   sync.Map
	proxySort, redirSort []string
	redirRegex           []*regexp.Regexp
)

// fixProxy proxies requests to the local server if the proxy's URL cannot be parsed
func fixProxy(u *url.URL, loc string) *url.URL {
	u = &url.URL{
		Scheme: "http",
		Host:   "localhost",
		Path:   strings.TrimPrefix(u.String(), "/"+loc),
	}
	if conf.HSTS {
		u.Scheme = "https"
		if conf.Adv.HTTPS != 443 {
			u.Host = u.Host + ":" + strconv.Itoa(conf.Adv.HTTPS)
		}
	} else if conf.Adv.HTTP != 80 {
		u.Host = u.Host + ":" + strconv.Itoa(conf.Adv.HTTP)
	}

	return u
}

// GetProxy finds the correct proxy index to use from the conf.Proxy struct
func GetProxy(r *http.Request) (string, string) {
	urlp := strings.Split(getFormattedURL(r), "/")

	if i := sort.SearchStrings(proxySort, r.Host); i < len(proxySort) && proxySort[i] == r.Host {
		if val, ok := proxyMap.Load(r.Host); ok {
			return val.(string), r.Host
		}
	}

	if i := sort.SearchStrings(proxySort, urlp[1]); i < len(proxySort) && proxySort[i] == urlp[1] {
		if val, ok := proxyMap.Load(urlp[1]); ok {
			return val.(string), urlp[1]
		}
	}

	return "", ""
}

// GetRedir returns the location a url should redirect to.
func GetRedir(r *http.Request, url string) string {
	if val, ok := redirMap.Load(r.Host + url); ok {
		return val.(string)
	}

	for _, re := range redirRegex {
		if re.FindString(r.Host+url) == r.Host+url {
			if val, ok := redirMap.Load(re.String()); ok {
				return val.(string)
			}
		}
	}

	return ""
}

// MakeProxyMap converts conf.Proxy and conf.Redir into a map, sorts them, and then compiles any regex used.
func MakeProxyMap() {
	proxySort, redirSort = []string{}, []string{}
	redirRegex = []*regexp.Regexp{}
	for i := range conf.Proxy {
		proxyMap.Store(conf.Proxy[i].Loc, conf.Proxy[i].URL)
		proxySort = append(proxySort, conf.Proxy[i].Loc)
	}
	for i := range conf.Redir {
		redirMap.Store(conf.Redir[i].Loc, conf.Redir[i].URL)
		redirSort = append(redirSort, conf.Redir[i].Loc)

		regex, err := regexp.Compile(conf.Redir[i].Loc)
		if err == nil && (strings.Contains(conf.Redir[i].Loc, `\/`) || !strings.ContainsAny(conf.Redir[i].Loc, "/")) {
			redirRegex = append(redirRegex, regex)
		}
	}
	sort.Strings(proxySort)
	sort.Strings(redirSort)
	sort.Strings(conf.No)
}

// ProxyRequest reverse-proxies a request, or websocket
func ProxyRequest(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Connection"), "Upgrade") && strings.Contains(r.Header.Get("Upgrade"), "websocket") {
		wsproxy.ServeHTTP(w, r)
	} else {
		proxy.ServeHTTP(w, r)
	}
}

// CheckUpdate checks if you are using the latest version of KatWeb.
// It will return 0 if KatWeb is up to date, -1 if a development version is being used, and 1 if an older version of KatWeb is being used.
// If the KatWeb release being used is behind by multiple versions, 2 will be returned.
// It will also return the latest version from the GitHub API as a string.
func CheckUpdate(current string) (int, string, error) {
	var upd UpdateData

	resp, err := updateClient.Get("https://api.github.com/repos/kittyhacker101/KatWeb/releases/latest")
	if err != nil {
		return 0, "", errors.New("unable to contact GitHub API")
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, "", errors.New("unable to read request body")
	}
	if json.Unmarshal(body, &upd) != nil {
		return 0, "", errors.New("unable to parse GitHub API response")
	}
	if upd.Latest == "" {
		return 0, "", errors.New("the GitHub API response is empty")
	}

	latesti, err := strconv.ParseFloat(upd.Latest[3:], 32)
	if err != nil {
		return 0, upd.Latest, errors.New("unable to parse latest version number")
	}

	if strings.HasSuffix(current, "-dev") {
		return -1, upd.Latest, nil
	}

	currenti, err := strconv.ParseFloat(current[3:], 32)
	if err != nil {
		return 0, upd.Latest, errors.New("unable to parse version number")
	}

	if math.Round(currenti) < math.Round(latesti) {
		return 2, upd.Latest, nil
	}
	if currenti < latesti {
		return 1, upd.Latest, nil
	}
	if currenti > latesti {
		return -1, upd.Latest, nil
	}

	return 0, upd.Latest, nil
}
