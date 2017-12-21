/* KatWeb by kittyhacker101.
This file contains KatWeb APIs, parts of KatWeb which normally stay the same, and are easy to interface with.
Changes to an API's functionality, or additions/deletions of APIs will appear in the changelog.
KatWeb APIs are also useful if you wish to modify KatWeb a large amount, as they are very flexible. */
package main

import (
	"compress/gzip"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// -------- KatWeb Configuration Presets --------

var (
	// tlsc provides an TLS configuration, for use in http.Server
	tlsc = &tls.Config{
		NextProtos:               []string{"h2", "http/1.1"},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// transport and client for any http.Client used to grab data from other servers
	transport = &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   30 * time.Second,
	}
	client = &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
)

// -------- KatWeb Function Snippets (parts of APIs) --------

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// director contains a director for use in httputil.ReverseProxy
func director(r *http.Request) {
	r.URL, _ = url.Parse(conf.Proxy.URL + strings.TrimPrefix(r.URL.EscapedPath(), "/"+conf.Proxy.Loc))
}

// -------- KatWeb Function APIs --------

/* DetectPasswd checks if a folder is set to be protected, and retrive the authentication credentials if required.
Inputs are (finfo, url, path).
Output will be provided in a string array, with [username, password] format.
If an error occures, ["err"] will be the output. */
func DetectPasswd(finfo os.FileInfo, url string, path string) []string {
	var tmp string

	if finfo.IsDir() {
		tmp = url
	} else {
		tmp = strings.TrimSuffix(url, finfo.Name())
	}

	b, err := ioutil.ReadFile(path + tmp + "passwd")
	if err == nil {
		tmpa := strings.Split(strings.TrimSpace(string(b)), ":")
		if len(tmpa) == 2 {
			return tmpa
		}
	}

	return []string{"err"}
}

/* DetectPath allows dynamic content control by domain.
Inputs are (r.Host+"/", r.URL.EscapedPath(), conf.Cache.Loc, conf.Proxy.Loc). Outputs are path and url.
Note that this is not a fully external API currently, it still has some dependencies on KatWeb code. */
func DetectPath(path string, url string, cache string, proxy string) (string, string) {
	if cache != "norun" && strings.HasPrefix(url, "/"+cache) {
		return cache + "/", strings.TrimPrefix(url, "/"+cache)
	}

	if proxy != "norun" {
		if strings.HasPrefix(url, "/"+proxy) || strings.TrimSuffix(path, "/") == proxy {
			return proxy, url
		}
	}

	_, err := os.Stat(path)
	if err == nil && path != "ssl/" {
		return path, url
	}

	return "html/", url
}

/* MakeGzipHandler adds a gzip wrapper to a http.HandlerFunc.
Inputs are (http.HandlerFunc, conf.Zip.Lvl).
Output will be a http.HandlerFunc. */
func MakeGzipHandler(funct http.HandlerFunc, level int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			funct(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gz, err := gzip.NewWriterLevel(w, level)
		if err != nil {
			gz = gzip.NewWriter(w)
		}
		defer gz.Close()

		gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		funct(gzr, r)
	}
}

/* RunAuth runs HTTP basic authentication on a http.Request.
Inputs are (http.ResponseWriter, *http.Request, []string{username, password}).
Output will be true if login is correct, false if login is incorrect. */
func RunAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	user, pass, _ := r.BasicAuth()
	if len(a) == 2 && user == a[0] && pass == a[1] {
		return true
	}

	return false
}

// -------- End of File --------
