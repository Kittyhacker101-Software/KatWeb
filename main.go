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
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
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
	Pro      bool `json:"protect"`
	Le       struct {
		Run bool     `json:"enabled"`
		Loc []string `json:"domains"`
	} `json:"letsencrypt"`
	Pef struct {
		Log bool `json:"logging"`
		GZ  int  `json:"gzipx"`
	} `json:"performance"`
	Proxy []struct {
		Loc string `json:"location"`
		URL string `json:"host"`
	} `json:"proxy"`
	Redir []struct {
		Loc string `json:"location"`
		URL string `json:"dest"`
	} `json:"redir"`
	Name  string `json:"name"`
	HTTP  int    `json:"httpPort"`
	HTTPS int    `json:"sslPort"`
}

const typeProxy = "proxy%"

var (
	conf Conf

	certManager = &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("ssl"),
	}

	rootl = flag.String("root", ".", "Root folder location")

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
		if conf.HTTP != 80 {
			host = strings.TrimSuffix(host, ":"+strconv.Itoa(conf.HTTP))
		}
		if conf.HTTPS != 443 {
			host = host + ":" + strconv.Itoa(conf.HTTPS)
		}

		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+host+r.URL.EscapedPath(), http.StatusMovedPermanently)
	})
)

// Log logs a request to the console.
func Log(r *http.Request, head string, url string) {
	if conf.Pef.Log {
		os.Stdout.WriteString("[" + head + "][" + r.Host + url + "] : " + r.RemoteAddr + "\n")
	}
}

// runAuth runs basic authentication on a http.Request
func runAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	if user, pass, _ := r.BasicAuth(); len(a) == 2 && user == a[0] && pass == a[1] {
		return true
	}

	return false
}

// detectPasswd gets password protection settings, and authentication credentials.
func detectPasswd(url string, path string) ([]string, bool) {
	tmp, _ := filepath.Split(url)

	if b, err := ioutil.ReadFile(path + tmp + "passwd"); err == nil {
		if tmpa := strings.Split(strings.TrimSpace(string(b)), ":"); len(tmpa) == 2 {
			return tmpa, true
		}
	}

	return []string{"err"}, false
}

// redir does an HTTP permanent redirect without making the path absolute.
func redir(w http.ResponseWriter, loc string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusMovedPermanently)
}

// detectPath allows dynamic content control by domain and path.
func detectPath(path string, url string, r *http.Request) (string, string) {
	if len(conf.Proxy) > 0 {
		prox, _ := GetProxy(r)
		if prox != "" {
			return prox, typeProxy
		}
	}

	if _, err := os.Stat(path); err == nil && path != "ssl/" {
		return path, url
	}

	return "html/", url
}

// loadHeaders adds headers from the server configuration to the request.
func loadHeaders(w http.ResponseWriter, r *http.Request, exists bool) {
	if conf.Name != "" {
		w.Header().Add("Server", conf.Name)
	}
	if r.TLS == nil {
		w.Header().Add("Keep-Alive", "timeout="+strconv.Itoa(conf.DatTime*4))
	}
	if conf.HSTS {
		w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains;preload")
	}

	if conf.Pro {
		w.Header().Add("Referrer-Policy", "no-referrer")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-Frame-Options", "sameorigin")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
	}

	if exists && conf.CachTime != 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
		w.Header().Set("Expires", time.Now().UTC().Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
	}
}

// mainHandle handles all requests given to the http.Server
func mainHandle(w http.ResponseWriter, r *http.Request) {
	var (
		authg bool
		auth  []string
	)

	// Get the correct content control options for the file.
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

	// Check the file's password protection options.
	finfo, err := os.Stat(path + url)
	if err == nil {
		auth, authg = detectPasswd(url, path)
	}

	loadHeaders(w, r, err == nil)

	// Apply any required redirects.
	if strings.HasSuffix(url, IndexFile) {
		redir(w, "./")
		return
	}
	if err == nil && finfo.IsDir() && !strings.HasSuffix(url, "/") {
		redir(w, r.URL.EscapedPath()+"/")
		return
	}
	if val, ok := redirMap.Load(r.Host + url); ok {
		http.Redirect(w, r, val.(string), http.StatusMovedPermanently)
	}

	// Provide an error message if the content is unavailable, and run authentication if required.
	if err != nil {
		StyledError(w, "404 Not Found", "The requested resource could not be found but may be available in the future.", http.StatusNotFound)
		Log(r, "WebNotFound", url)
		return
	}
	if finfo.Name() == "passwd" {
		StyledError(w, "403 Forbidden", "You do not have permission to access this resource.", http.StatusForbidden)
		Log(r, "WebForbid", url)
		return
	}
	if authg && !runAuth(w, r, auth) {
		StyledError(w, "401 Unauthorized", "Correct authentication credentials are required to access this resource.", http.StatusUnauthorized)
		Log(r, "WebUnAuth", url)
		return
	}
	if r.Method == "BREW" {
		StyledError(w, "418 I'm a Teapot", "The requested entity body is short and stout. Tip me over and pour me out.", http.StatusTeapot)
		Log(r, "WebTeapot", url)
		return
	}

	// Serve the content, and return an error if needed
	if ServeFile(w, r, path+url, url) != nil {
		StyledError(w, "500 Internal Server Error", "An unexpected condition was encountered, try again later", http.StatusInternalServerError)
		Log(r, "WebError", url)
		return
	}

	// Log the response to the console
	if conf.Pef.Log {
		if r.Method == "POST" && r.ParseForm() == nil {
			fmt.Println("[WebForm]["+r.Host+url+"] : "+r.RemoteAddr+" :", r.PostForm)
		} else {
			Log(r, "Web", url)
		}
	}
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
	fmt.Println("Loading KatWeb...")
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
		Addr:         ":" + strconv.Itoa(conf.HTTPS),
		Handler:      http.HandlerFunc(mainHandle),
		TLSConfig:    tlsc,
		ReadTimeout:  time.Duration(conf.DatTime) * time.Second,
		WriteTimeout: time.Duration(conf.DatTime) * time.Second,
		IdleTimeout:  time.Duration(conf.DatTime*4) * time.Second,
	}
	// srvh handles all configuration for HTTP.
	srvh := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTP),
		Handler:      wrapLoad(mainHandle),
		ReadTimeout:  time.Duration(conf.DatTime) * time.Second,
		WriteTimeout: time.Duration(conf.DatTime) * time.Second,
		IdleTimeout:  time.Duration(conf.DatTime*4) * time.Second,
	}

	// Handle graceful shutdown from crtl+c
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("Shutting down KatWeb...")
		srv.Shutdown(context.Background())
		srvh.Shutdown(context.Background())
		os.Exit(1)
	}()

	fmt.Println("KatWeb Server Started. Server errors will be printed into the console.")

	go srvh.ListenAndServe()
	fmt.Println(srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key"))
}
