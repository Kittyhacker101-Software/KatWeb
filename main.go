// KatWeb by kittyhacker101
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Conf contains all configuration fields for the server.
type Conf struct {
	CachTime int  `json:"cachingTimeout"`
	DatTime  int  `json:"streamTimeout"`
	HSTS     bool `json:"hsts"`
	Le       struct {
		Run bool     `json:"enabled"`
		Loc []string `json:"domains"`
	} `json:"letsencrypt"`
	Proxy []struct {
		Loc string `json:"location"`
		URL string `json:"host"`
	} `json:"proxy"`
	Redir []struct {
		Loc string `json:"location"`
		URL string `json:"dest"`
	} `json:"redir"`
	Adv struct {
		Dev   bool `json:"devmode"`
		Pro   bool `json:"protect"`
		HTTP  int  `json:"httpPort"`
		HTTPS int  `json:"sslPort"`
	} `json:"advanced"`
}

const typeProxy = "proxy%"

var (
	conf Conf

	certManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("ssl"),
	}

	rootl = flag.String("root", ".", "Root folder location")
	svrh  = flag.String("serverName", "KatWeb", `String set in the "server" HTTP header.`)

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
			// NOTE: Please compile with TLS-Tris if you would like to take advantage of TLS 1.3
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
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
		Log(r, "WebHSTS", r.URL.EscapedPath())
	})
)

// Log logs a request to the console.
func Log(r *http.Request, head string, url string) {
	if !conf.Adv.Dev && (head == "WebProxy" || head == "Web" || head == "WebHSTS" || head == "WebRedir") {
		return
	}

	host := r.Host
	if strings.Contains(r.Host, ":") {
		host = strings.Split(r.Host, ":")[0]
	}
	os.Stdout.WriteString("[" + head + "][" + host + url + "] : " + r.RemoteAddr + "\n")
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
		Log(r, "WebBad", urlo)
		return
	}

	path, url := detectPath(r.Host+"/", urlo, r)
	if url == typeProxy {
		ProxyRequest(w, r)
		Log(r, "WebProxy", urlo)
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
		Log(r, "WebRedir", r.URL.EscapedPath())
		return
	}

	// Don't allow the client to access .. or . folders, and don't allow access to hidden files.
	// Also, don't allow access to the root folder.
	if strings.Contains(url, "..") || path == "ssl/" || path[0] == 46 || path[0] == 47 {
		StyledError(w, "403 Forbidden", "You do not have permission to access this resource.", http.StatusForbidden)
		Log(r, "WebForbid", url)
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
		Log(r, "WebNotFound", url)
		return
	}
	auth := DetectPasswd(url, path)
	if finfo.Name() == "passwd" || auth[0] == "forbid" {
		StyledError(w, "403 Forbidden", "You do not have permission to access this resource.", http.StatusForbidden)
		Log(r, "WebForbid", url)
		return
	}
	if auth[0] != "err" && !RunAuth(w, r, auth) {
		StyledError(w, "401 Unauthorized", "Correct authentication credentials are required to access this resource.", http.StatusUnauthorized)
		Log(r, "WebUnAuth", url)
		return
	}

	// Serve the content, and return an error if needed
	if ServeFile(w, r, path+url, url) != nil {
		StyledError(w, "500 Internal Server Error", "An unexpected condition was encountered, try again later", http.StatusInternalServerError)
		Log(r, "WebError", url)
		return
	}

	Log(r, "Web", url)
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

func main() {
	flag.Parse()
	fmt.Println("[Info] : Loading KatWeb...")
	os.Chdir(*rootl)

	data, err := ioutil.ReadFile("conf.json")
	if err != nil {
		fmt.Println("[Fatal] : Unable to read config file! Debugging info will be printed below.")
		fmt.Println(err)
		os.Exit(1)
	}
	if json.Unmarshal(data, &conf) != nil {
		fmt.Println("[Fatal] : Unable to parse config file!")
		os.Exit(1)
	}

	debug.SetGCPercent(720)
	MakeProxyMap()

	// srv handles all configuration for HTTPS.
	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(conf.Adv.HTTPS),
		Handler:           http.HandlerFunc(mainHandle),
		TLSConfig:         tlsc,
		ErrorLog:          Logger,
		MaxHeaderBytes:    2048,
		ReadTimeout:       time.Duration(conf.DatTime) * time.Second,
		ReadHeaderTimeout: time.Duration(conf.DatTime/2) * time.Second,
		WriteTimeout:      time.Duration(conf.DatTime) * time.Second,
		IdleTimeout:       time.Duration(conf.DatTime*4) * time.Second,
	}
	// srvh handles all configuration for HTTP.
	srvh := &http.Server{
		Addr:              ":" + strconv.Itoa(conf.Adv.HTTP),
		Handler:           wrapLoad(mainHandle),
		ErrorLog:          Logger,
		MaxHeaderBytes:    2048,
		ReadTimeout:       time.Duration(conf.DatTime) * time.Second,
		ReadHeaderTimeout: time.Duration(conf.DatTime/2) * time.Second,
		WriteTimeout:      time.Duration(conf.DatTime) * time.Second,
		IdleTimeout:       time.Duration(conf.DatTime*4) * time.Second,
	}

	// Handle graceful shutdown from crtl+c
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n[Info] : Shutting down KatWeb...")
		srv.Shutdown(context.Background())
		srvh.Shutdown(context.Background())
		os.Exit(0)
	}()

	// Reload config when a SIGHUP is recived
	cr := make(chan os.Signal, 1)
	signal.Notify(cr, syscall.SIGHUP)
	go func() {
		for {
			<-cr
			fmt.Println("[Info] : Reloading config...")
			data, err := ioutil.ReadFile("conf.json")
			if err != nil {
				fmt.Println("[Error] : Unable to read config file!")
				continue
			}
			if json.Unmarshal(data, &conf) != nil {
				fmt.Println("[Error] : Unable to parse config file!")
				continue
			}
			MakeProxyMap()
			fmt.Println("[Info] : Config reloaded.")
		}
	}()

	fmt.Println("[Info] : KatWeb Started.")

	go srvh.ListenAndServe()
	fmt.Println(srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key"))
	os.Exit(1)
}
