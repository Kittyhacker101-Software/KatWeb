// KatWeb HTTP Server
package main

import (
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Conf contains all the fields for the JSON Config file of the server.
type Conf struct {
	IdleTime int `json:"keepAliveTimeout"`
	CachTime int `json:"cachingTimeout"`
	DatTime  int `json:"streamTimeout"`
	HSTS     struct {
		Run bool `json:"enabled"`
		Mix bool `json:"mixedssl"`
		Sub bool `json:"includeSubDomains"`
		Pre bool `json:"preload"`
	} `json:"hsts"`
	Pro bool `json:"protect"`
	Zip struct {
		Run bool `json:"enabled"`
		Lvl int  `json:"level"`
	} `json:"gzip"`
	Cache struct {
		Run bool `json:"enabled"`
		Up  int  `json:"updates"`
	} `json:"hcache"`
	Proxy struct {
		Run  bool   `json:"enabled"`
		Type string `json:"type"`
		Host string `json:"host"`
	} `json:"proxy"`
	Name  string `json:"name"`
	HTTP  int    `json:"httpPort"`
	HTTPS int    `json:"sslPort"`
}

var (
	handleReq  http.Handler
	handleHTTP http.Handler
	conf       Conf
	path       string
	cacheA     = []string{"html/"}
	cacheB     = []string{"ssl/", "cache/"}
)

// tlsc provides a SSL config that is more secure than Golang's default.
var tlsc = &tls.Config{
	PreferServerCipherSuites: true,
	CurvePreferences: []tls.CurveID{
		tls.CurveP256,
		tls.X25519,
	},
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	},
}

// checkIntact peforms all pre-startup checks.
func checkIntact() {
	_, err := os.Stat("ssl/server.crt")
	_, err1 := os.Stat("ssl/server.key")
	if err != nil || err1 != nil {
		fmt.Println("[Fatal] : SSL Certs do not exist!")
		os.Exit(1)
	}

	if conf.HTTP != 80 || conf.HTTPS != 443 {
		fmt.Println("[Warn] : Dynamic Serving will not work on non-standard ports!")
		if conf.HSTS.Run {
			fmt.Println("[Warn] : HSTS will not work on non-standard ports!")
			conf.HSTS.Run = false
		}
	}

	if conf.IdleTime == 0 && conf.HSTS.Mix {
		fmt.Println("[Warn] : Mixed SSL requires HTTP Keep Alive!")
		conf.HSTS.Mix = false
	}

	if conf.HSTS.Run {
		if conf.HSTS.Mix {
			fmt.Println("[Warn] : Mixed SSL and HSTS can not be both enabled!")
			conf.HSTS.Mix = false
		}
	} else {
		if conf.Zip.Run && conf.Proxy.Run {
			fmt.Println("[Warn] : HTTP Reverse Proxy will not work with Gzip!")
			conf.Zip.Run = false
		}
	}

	if conf.Cache.Run {
		_, err = os.Stat("cache")
		if err != nil {
			fmt.Println("[Warn] : Cache folder does not exist!")
			conf.Cache.Run = false
		}
	}

	conf.Proxy.Type = strings.ToLower(conf.Proxy.Type)
	if conf.Proxy.Run && conf.Proxy.Type != "http" && conf.Proxy.Type != "https" {
		fmt.Println("[Warn] : HTTP Reverse Proxy will only work with HTTP or HTTPS connections.")
		conf.Zip.Run = false
	}

	_, err = os.Stat("html")
	if err != nil {
		fmt.Println("[Warn] : HTML folder does not exist!")
	}

	if conf.DatTime <= 4 {
		fmt.Println("[Warn] : Setting a low stream timeout may result in issues with high latency connections.")
	}

	if conf.Cache.Run && conf.Cache.Up <= 0 {
		conf.Cache.Run = false
	}

}

// detectPath handles dynamic content control by domain.
func detectPath(p string) string {

	// We check to see if the domain is stored in the cache.
	loc := sort.SearchStrings(cacheB, p)
	if loc < len(cacheB) && cacheB[loc] == p {
		return "html/"
	}
	loc = sort.SearchStrings(cacheA, p)
	if loc < len(cacheA) && cacheA[loc] == p {
		return p
	}

	// If it's not in the cache, check the hard disk, and add it to the cache.
	_, err := os.Stat(p)
	if err != nil {
		cacheB = append(cacheB, p)
		sort.Strings(cacheB)
		return "html/"
	}

	cacheA = append(cacheA, p)
	sort.Strings(cacheA)
	return p
}

// detectPasswd checks if the folder needs to be password protected.
func detectPasswd(i os.FileInfo, p string) string {
	var tmpl string
	if i.IsDir() {
		tmpl = p

	} else {
		tmpl = strings.TrimSuffix(p, i.Name())
	}
	b, err := ioutil.ReadFile(path + tmpl + "/passwd")
	if err == nil {
		return strings.TrimSpace(string(b))
	}
	return "err"
}

// runAuth handles HTTP Basic Authentication.
func runAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 || pair[0] != a[0] || pair[1] != a[1] {
		return false
	}

	return true
}

// wrapLoad chooses the correct wrappers based on server configuration.
func wrapLoad(origin http.HandlerFunc) (http.Handler, http.Handler) {
	tmpR := origin

	if conf.Zip.Run {
		tmpR = makeGzipHandler(origin)
	}

	tmpH := tmpR
	if conf.HSTS.Run {
		tmpH = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Connection", "close")
			http.Redirect(w, r, "https://"+r.Host+r.URL.EscapedPath(), http.StatusMovedPermanently)
			fmt.Println("[WebHSTS][" + r.Host + r.URL.EscapedPath() + "] : " + r.RemoteAddr)
		})
	}

	return tmpR, tmpH
}

// updateCache handles automatically updating the Basic HTTP Cache.
func updateCache() {
	fmt.Println("KatWeb HTTP Cache Started.")
	tr := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: tr}
	for {
		err0 := filepath.Walk("cache/", func(path string, info os.FileInfo, errw error) error {
			if errw != nil {
				fmt.Println("[Cache][Warn] : Unable to get filepath info!")
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(path, ".txt") {
				fmt.Println("[Cache][HTTP] : Updating " + strings.TrimSuffix(path, ".txt") + "...")
				b, err := ioutil.ReadFile(path)

				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to read " + path + "!")
					return nil
				}

				err = os.Remove(strings.TrimSuffix(path, ".txt"))
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to delete " + strings.TrimSuffix(path, ".txt") + "!")
				}

				out, err := os.Create(strings.TrimSuffix(path, ".txt"))
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to create " + strings.TrimSuffix(path, ".txt") + "!")
					return nil
				}

				resp, err := client.Get(strings.TrimSpace(string(b)))
				if resp != nil {
					defer resp.Body.Close()
				}
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to download " + strings.TrimSuffix(path, ".txt") + "!")
					return nil
				}

				_, err = io.Copy(out, resp.Body)
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to write " + strings.TrimSuffix(path, ".txt") + "!")
				}
			}
			return nil
		})
		if err0 != nil {
			fmt.Println("[Cache][Warn] : Unable to walk filepath!")
		} else {
			fmt.Println("[Cache][HTTP] : All files in HTTP Cache updated!")
		}
		time.Sleep(time.Duration(conf.Cache.Up) * time.Minute)
	}
}

// gzipResponseWriter handles the various writers needed for gzip compression.
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// makeGzipHandler uses those writers to gzip the content that needs to be sent.
func makeGzipHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			fn(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz, err := gzip.NewWriterLevel(w, conf.Zip.Lvl)
		if err != nil {
			fmt.Println("[Warn] : Unable to make gzip writer using configured compression value!")
			conf.Zip.Lvl = -1
			gz = gzip.NewWriter(w)
		}
		defer gz.Close()
		gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		fn(gzr, r)
	}
}

// The main function handles startup and webserver logic.
func main() {
	fmt.Println("Loading server...")

	// Load the config file, and then parse it into the conf struct.
	data, err := ioutil.ReadFile("conf.json")
	if err != nil {
		fmt.Println("[Fatal] : Unable to read config file!")
		os.Exit(1)
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		fmt.Println("[Fatal] : Unable to parse config file!")
		os.Exit(1)
	}

	checkIntact()

	// UTC time is required for HTTP Caching headers.
	location, err := time.LoadLocation("UTC")
	if err != nil {
		fmt.Println("[Warn] : Unable to load timezones!")
		conf.CachTime = 0
	}

	// mainHandle handles all HTTP Web Requests, all other handlers in here are just wrappers.
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		var (
			authg bool
			auth  []string
		)

		// Get file info, and check Dynamic Content Control settings.
		url := r.URL.EscapedPath()
		path = detectPath(r.Host + "/")
		if strings.HasPrefix(path, "html") {
			if strings.HasPrefix(url, "/cache") {
				path = "cache/"
				url = strings.TrimPrefix(url, "/cache")
			} else if conf.Proxy.Run && strings.HasPrefix(url, "/proxy") {
				// No headers are added, we will depend on the proxied server to provide those.
				director := func(req *http.Request) {
					req = r
					req.URL.Scheme = conf.Proxy.Type
					req.URL.Host = conf.Proxy.Host
				}
				proxy := &httputil.ReverseProxy{Director: director}
				proxy.ServeHTTP(w, r)
				fmt.Println("[WebProxy][" + r.Host + url + "] : " + r.RemoteAddr)
				return
			}
		}

		// Enable password protection of a folder if needed.
		finfo, err := os.Stat(path + url)
		if err == nil {
			tmp := detectPasswd(finfo, url)
			if tmp != "err" {
				auth = strings.Split(tmp, ":")
				if len(auth) == 2 {
					authg = true
				}
			}
		}

		// Add important headers
		if conf.Name != "" {
			w.Header().Add("Server", conf.Name)
		}
		if conf.IdleTime != 0 {
			w.Header().Add("Keep-Alive", "timeout="+strconv.Itoa(conf.IdleTime))
		}
		if conf.HSTS.Run {
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
			w.Header().Add("Alt-Svc", `h2=":`+strconv.Itoa(conf.HTTPS)+`"; ma=`+strconv.Itoa(conf.IdleTime))
		}

		// Check if a redirect is present, and apply the redirect if needed.
		if err != nil {
			b, err := ioutil.ReadFile(path + url + ".redir")
			if err == nil {
				http.Redirect(w, r, strings.TrimSpace(string(b)), http.StatusPermanentRedirect)
				fmt.Println("[Web302][" + r.Host + url + "] : " + r.RemoteAddr)
				return
			}
		}

		// Add file headers, then send data.
		if err != nil {
			http.Error(w, "404 Not Found : The requested resource could not be found but may be available in the future.", 404)
			fmt.Println("[Web404][" + r.Host + url + "] : " + r.RemoteAddr)
		} else {
			if conf.CachTime != 0 {
				w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
				w.Header().Set("Expires", time.Now().In(location).Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
			}
			if conf.Pro {
				w.Header().Add("X-Content-Type-Options", "nosniff")
				w.Header().Add("X-Frame-Options", "sameorigin")
				w.Header().Add("X-XSS-Protection", "1; mode=block")
			}

			if authg {
				if finfo.Name() == "passwd" {
					http.Error(w, "403 Forbidden : The request was valid, but the server is refusing action. The user might not have the necessary permissions for a resource.", 403)
					fmt.Println("[Web403][" + r.Host + url + "] : " + r.RemoteAddr)
				} else if runAuth(w, r, auth) {
					http.ServeFile(w, r, path+url)
					fmt.Println("[WebAuth][" + r.Host + url + "] : " + r.RemoteAddr)
				} else {
					http.Error(w, "401 Unauthorized : Authentication is required and has failed or has not yet been provided.", 401)
					fmt.Println("[Web401][" + r.Host + url + "] : " + r.RemoteAddr)
				}
			} else {
				http.ServeFile(w, r, path+url)
				fmt.Println("[Web][" + r.Host + url + "] : " + r.RemoteAddr)
			}
		}
	}

	handleReq, handleHTTP = wrapLoad(mainHandle)

	// srv handles all configuration for HTTPS.
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTPS),
		Handler:      handleReq,
		TLSConfig:    tlsc,
		ReadTimeout:  time.Duration(conf.DatTime) * time.Second,
		WriteTimeout: time.Duration(conf.DatTime*2) * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}
	// srvh handles all configuration for HTTP.
	srvh := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTP),
		Handler:      handleHTTP,
		ReadTimeout:  time.Duration(conf.DatTime) * time.Second,
		WriteTimeout: time.Duration(conf.DatTime*2) * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}

	// Run HTTP Cache auto update, and start the HTTP/HTTPS servers.
	if conf.Cache.Run {
		go updateCache()
	}

	fmt.Println("KatWeb HTTP Server Started.")
	go srvh.ListenAndServe()
	srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key")
	fmt.Println("[Fatal] : KatWeb was unable to start!")
}
