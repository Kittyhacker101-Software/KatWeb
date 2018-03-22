// KatWeb by kittyhacker101
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Conf contains all configuration fields for the server.
type Conf struct {
	CachTime int `json:"cachingTimeout"`
	DatTime  int `json:"streamTimeout"`
	HSTS     struct {
		Run bool `json:"enabled"`
		Mix bool `json:"mixedssl"`
		Sub bool `json:"includeSubDomains"`
		Pre bool `json:"preload"`
	} `json:"hsts"`
	Pro bool `json:"protect"`
	Pef struct {
		Log    bool    `json:"logging"`
		Thread int     `json:"threads"`
		GC     float32 `json:"gcx"`
		GZ     int     `json:"gzipx"`
	} `json:"performance"`
	Proxy struct {
		Run bool   `json:"enabled"`
		Loc string `json:"location"`
		URL string `json:"host"`
	} `json:"proxy"`
	Name  string `json:"name"`
	HTTP  int    `json:"httpPort"`
	HTTPS int    `json:"sslPort"`
}

var (
	conf     Conf
	location *time.Location

	// tlsc provides an TLS configuration for use with http.Server
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

	proxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL, _ = url.Parse(conf.Proxy.URL + strings.TrimPrefix(r.URL.EscapedPath(), "/"+conf.Proxy.Loc))
		},
		Transport: &http.Transport{
			IdleConnTimeout: time.Duration(conf.DatTime*4) * time.Second,
		},
	}

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

// checkIntact validates the server configuration.
func checkIntact() {
	if conf.HSTS.Mix {
		fmt.Println("[Warn] : Mixed SSL requires HTTP Keep Alive!")
		conf.HSTS.Mix = false
	}

	if _, err := os.Stat("html"); err != nil {
		fmt.Println("[Warn] : HTML folder does not exist!")
	}

	if conf.DatTime <= 4 {
		fmt.Println("[Warn] : Setting a low stream timeout may result in issues with high latency connections.")
	}

	if conf.Pef.Thread > 0 {
		runtime.GOMAXPROCS(conf.Pef.Thread)
	}
	debug.SetGCPercent(int(conf.Pef.GC * 100))
}

// detectPasswd gets password protection settings, and authentication credentials.
func detectPasswd(url string, path string) ([]string, bool) {
	tmp, _ := filepath.Split(url)

	b, err := ioutil.ReadFile(path + tmp + "passwd")
	if err == nil {
		tmpa := strings.Split(strings.TrimSpace(string(b)), ":")
		if len(tmpa) == 2 {
			return tmpa, true
		}
	}

	return []string{"err"}, false
}

// runAuth runs basic authentication on a http.Request
func runAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	user, pass, _ := r.BasicAuth()
	if len(a) == 2 && user == a[0] && pass == a[1] {
		return true
	}

	return false
}

// redir does an HTTP permanent redirect without making the path absolute.
func redir(w http.ResponseWriter, r *http.Request, loc string, url string) {
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusMovedPermanently)
	if conf.Pef.Log {
		fmt.Println("[WebRedir][" + r.Host + url + "] : " + r.RemoteAddr)
	}
}

// detectPath allows dynamic content control by domain and path.
func detectPath(path string, url string) (string, string) {
	if conf.Proxy.Run {
		if strings.HasPrefix(url, "/"+conf.Proxy.Loc) || strings.TrimSuffix(path, "/") == conf.Proxy.Loc {
			return conf.Proxy.Loc, url
		}
	}

	if _, err := os.Stat(path); err == nil && path != "ssl/" {
		return path, url
	}

	return "html/", url
}

// loadHeaders adds headers from the server configuration to the request.
func loadHeaders(w http.ResponseWriter, exists bool, l *time.Location) {
	if conf.Name != "" {
		w.Header().Add("Server", conf.Name)
	}
	w.Header().Add("Keep-Alive", "timeout="+strconv.Itoa(conf.DatTime*4))
	if conf.HSTS.Run {
		/* I may consider adding a config option for the max-age for HSTS, but it seems pointless to do so.
		If there is a legitimate use case for it, then I might consider adding it in the future. */
		if conf.HSTS.Sub {
			if conf.HSTS.Pre {
				w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains;preload")
			} else {
				w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains")
			}
		} else {
			// HSTS Preload requires includeSubDomains.
			w.Header().Add("Strict-Transport-Security", "max-age=31536000")
		}
	} else if conf.HSTS.Mix {
		w.Header().Add("Alt-Svc", `h2=":`+strconv.Itoa(conf.HTTPS)+`"; ma=`+strconv.Itoa(conf.DatTime*4))
	}

	if conf.Pro {
		w.Header().Add("Referrer-Policy", "no-referrer")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-Frame-Options", "sameorigin")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
	}

	if exists && conf.CachTime != 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
		w.Header().Set("Expires", time.Now().In(l).Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
	}
}

// mainHandle handles all requests given to the http.Server
func mainHandle(w http.ResponseWriter, r *http.Request) {
	var (
		authg bool
		auth  []string
	)

	// Get the correct content control options for the file.
	path, url := detectPath(r.Host+"/", r.URL.EscapedPath())
	if path == conf.Proxy.Loc {
		proxy.ServeHTTP(w, r)
		if conf.Pef.Log {
			fmt.Println("[WebProxy][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}

	// Check the file's password protection options.
	finfo, err := os.Stat(path + url)
	if err == nil {
		auth, authg = detectPasswd(url, path)
	}

	loadHeaders(w, err == nil, location)

	// Apply any required redirects.
	b, err2 := ioutil.ReadFile(path + url + ".redir")
	if err2 == nil {
		http.Redirect(w, r, strings.TrimSpace(string(b)), http.StatusPermanentRedirect)
		if conf.Pef.Log {
			fmt.Println("[WebRedir][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}
	if strings.HasSuffix(url, "index.html") {
		redir(w, r, "./", url)
		return
	}
	if err == nil && finfo.IsDir() && !strings.HasSuffix(url, "/") {
		redir(w, r, r.URL.EscapedPath()+"/", url)
		return
	}

	// Provide an error message if the content is unavailable, and run authentication if required.
	if err != nil {
		http.Error(w, "404 Not Found : The requested resource could not be found but may be available in the future.", http.StatusNotFound)
		if conf.Pef.Log {
			fmt.Println("[WebNotFound][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}
	if finfo.Name() == "passwd" {
		http.Error(w, "403 Forbidden : The request was valid, but the server is refusing action.", http.StatusForbidden)
		if conf.Pef.Log {
			fmt.Println("[WebForbid][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}
	if authg && !runAuth(w, r, auth) {
		http.Error(w, "401 Unauthorized : Authentication is required and has failed or has not yet been provided.", http.StatusUnauthorized)
		if conf.Pef.Log {
			fmt.Println("[WebUnAuth][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}

	err = ServeFile(w, r, path+url, url)
	if err != nil {
		http.Error(w, "500 Internal Server Error : An unexpected condition was encountered.", http.StatusInternalServerError)
		fmt.Println("[WebError][" + r.Host + r.URL.EscapedPath() + "] : " + r.RemoteAddr)
		return
	}

	// Log the response to the console
	if conf.Pef.Log {
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				fmt.Printf("[WebForm]["+r.Host+url+"][%v] : "+r.RemoteAddr+"\n", r.PostForm)
			} else {
				fmt.Println("[WebForm][" + r.Host + url + "][Error] : " + r.RemoteAddr)
			}
		} else {
			fmt.Println("[Web][" + r.Host + url + "] : " + r.RemoteAddr)
		}
	}
}

// wrapLoad chooses the correct handler wrappers based on server configuration.
func wrapLoad(origin http.HandlerFunc) http.Handler {
	if conf.HSTS.Run {
		return httpsredir
	}

	return MakeGzipHandler(origin)
}

func main() {
	fmt.Println("Loading KatWeb...")

	// Load, parse, and validate configuration.
	data, err := ioutil.ReadFile("conf.json")
	if err != nil {
		fmt.Println("[Fatal] : Unable to read config file! Debugging info will be printed below.")
		fmt.Println(err)
		os.Exit(1)
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		fmt.Println("[Fatal] : Unable to parse config file! Debugging info will be printed below.")
		fmt.Println(err)
		os.Exit(1)
	}
	checkIntact()

	// Load the correct timezone for caching headers.
	location, err = time.LoadLocation("UTC")
	if err != nil {
		fmt.Println("[Warn] : Unable to load timezones!")
		conf.CachTime = 0
	}

	// srv handles all configuration for HTTPS.
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTPS),
		Handler:      MakeGzipHandler(mainHandle),
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
