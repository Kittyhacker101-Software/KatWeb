// KatWeb by kittyhacker101 - HTTP request handling
package main

import (
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const typeProxy = "proxy%"

var (
	certManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("ssl"),
	}

	// httpsredir is a http.HandlerFunc for redirecting HTTP requests to HTTPS
	httpsredir = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if conf.Adv.HTTP != 80 {
			host = strings.TrimSuffix(host, ":"+strconv.Itoa(conf.Adv.HTTP))
		}
		if conf.Adv.HTTPS != 443 {
			host = host + ":" + strconv.Itoa(conf.Adv.HTTPS)
		}

		redir(w, "https://"+host+r.URL.EscapedPath())
		logr(r, "WebHSTS", r.URL.EscapedPath())
	})

	// Logger is a custom logger for net/http and httputil
	Logger = log.New(os.Stderr, "[Error] : ", 0)

	// tlsc provides an TLS configuration for use with http.Server
	tlsc = &tls.Config{
		NextProtos:               []string{"h2", "http/1.1"},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// Uncomment this section if you are compiling with TLS-Tris
			//tls.TLS_CHACHA20_POLY1305_SHA256,
			//tls.TLS_AES_256_GCM_SHA384,
			//tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
)

// logr logs a request to the console.
func logr(r *http.Request, head, url string) {
	if !conf.Adv.Dev && (head == "WebProxy" || head == "Web" || head == "WebHSTS" || head == "WebRedir" || head == "WebNotFound") {
		return
	}

	host := r.Host
	if strings.Contains(r.Host, ":") {
		host = strings.Split(r.Host, ":")[0]
	}
	Print("[" + head + "][" + host + url + "] : " + r.RemoteAddr)
}

// redir does an HTTP permanent redirect without making the path absolute.
func redir(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusMovedPermanently)
}

// detectPath allows dynamic content control by domain and path.
func detectPath(path string, url string, r *http.Request) (string, string) {
	if strings.Contains(path, ":") {
		path = strings.Split(path, ":")[0]
	}

	if len(conf.Proxy) > 0 {
		prox, _ := GetProxy(r)
		if prox != "" {
			return prox, typeProxy
		}
	}

	if _, err := os.Stat(path); err == nil {
		return path, url
	}

	return "html/", url
}

// loadHeaders adds headers from the server configuration to the request.
func loadHeaders(w http.ResponseWriter, r *http.Request) {
	if len(*svrh) > 0 {
		w.Header().Add("Server", *svrh)
	}
	if conf.HSTS {
		w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains;preload")
	}

	if conf.Adv.Pro {
		w.Header().Add("Referrer-Policy", "no-referrer")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("Content-Security-Policy", "default-src https: data: 'unsafe-inline' 'unsafe-eval' 'self'; frame-ancestors 'self'")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
	}

	if conf.CachTime != 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate="+strconv.Itoa(900*conf.CachTime))
	}
}

// mainHandle handles all requests given to the http.Server
func mainHandle(w http.ResponseWriter, r *http.Request) {
	urlo, err := url.QueryUnescape(r.URL.EscapedPath())
	if err != nil {
		StyledError(w, "400 Bad Request", "The server cannot process the request due to an apparent client error", http.StatusBadRequest)
		logr(r, "WebBad", urlo)
		return
	}

	path, url := detectPath(r.Host+"/", urlo, r)
	if url == typeProxy {
		ProxyRequest(w, r)
		logr(r, "WebProxy", urlo)
		return
	}

	loadHeaders(w, r)

	// Apply any required redirects.
	if strings.HasSuffix(url, IndexFile) {
		redir(w, "./")
		return
	}
	if val, ok := redirMap.Load(r.Host + url); ok {
		redir(w, val.(string))
		logr(r, "WebRedir", r.URL.EscapedPath())
		return
	}

	// Don't allow the client to access .. or . folders, and don't allow access to hidden files.
	// Also, don't allow access to the root folder.
	if strings.Contains(url, "..") || path == "ssl/" || path[0] == 46 || path[0] == 47 {
		StyledError(w, "403 Forbidden", "You do not have permission to access this resource.", http.StatusForbidden)
		logr(r, "WebForbid", url)
		return
	}

	// Check the file's password protection options.
	finfo, err := os.Stat(path + url)
	if err == nil {
		if finfo.IsDir() && !strings.HasSuffix(url, "/") {
			redir(w, r.URL.EscapedPath()+"/")
			return
		}
	}

	// Provide an error message if the content is unavailable, and run authentication if required.
	if err != nil {
		StyledError(w, "404 Not Found", "The requested resource could not be found but may be available in the future.", http.StatusNotFound)
		logr(r, "WebNotFound", url)
		return
	}
	auth := DetectPasswd(url, path)
	if finfo.Name() == "passwd" || auth[0] == "forbid" {
		StyledError(w, "403 Forbidden", "You do not have permission to access this resource.", http.StatusForbidden)
		logr(r, "WebForbid", url)
		return
	}
	if auth[0] != "err" && !RunAuth(w, r, auth) {
		StyledError(w, "401 Unauthorized", "Correct authentication credentials are required to access this resource.", http.StatusUnauthorized)
		logr(r, "WebUnAuth", url)
		return
	}

	// Serve the content, and return an error if needed
	if ServeFile(w, r, path+url, url) != nil {
		StyledError(w, "500 Internal Server Error", "An unexpected condition was encountered, try again later", http.StatusInternalServerError)
		logr(r, "WebError", url)
		return
	}

	logr(r, "Web", url)
}

// wrapLoad chooses the correct handler wrappers based on server configuration.
func wrapLoad(origin http.HandlerFunc) http.Handler {
	var wrap = origin

	if conf.HSTS {
		wrap = httpsredir
	}

	if conf.Le.Run {
		tlsc.GetCertificate = certManager.GetCertificate
		certManager.HostPolicy = autocert.HostWhitelist(conf.Le.Loc...)
		return certManager.HTTPHandler(wrap)
	}

	return wrap
}
