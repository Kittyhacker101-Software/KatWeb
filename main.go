// KatWeb by kittyhacker101
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/klauspost/compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Conf contains all configuration fields for the server.
type Conf struct {
	IdleTime int  `json:"keepAliveTimeout"`
	CachTime int  `json:"cachingTimeout"`
	DatTime  int  `json:"streamTimeout"`
	Log      bool `json:"logging"`
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
		Run bool   `json:"enabled"`
		Loc string `json:"location"`
		Up  int    `json:"updates"`
	} `json:"hcache"`
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

	// Added due to a naming conflict between a variable named url, and the net/url package.
	parse = url.Parse

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

	// transport and client settings for use with http.Client
	transport = &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   30 * time.Second,
	}
	client = &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	zippers = sync.Pool{New: func() interface{} {
		gz, err := gzip.NewWriterLevel(nil, conf.Zip.Lvl)
		if err != nil {
			fmt.Println("[Warn] : An error occurred while creating gzip writer!")
			gz = gzip.NewWriter(nil)
		}
		return gz
	}}

	htmlReplacer = strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	)
)

// makeGzipHandler creates a wrapper for an http.Handler with Gzip compression.
func makeGzipHandler(funct http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			funct(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gz := zippers.Get().(*gzip.Writer)
		gz.Reset(w)

		funct(gzipResponseWriter{Writer: gz, ResponseWriter: w}, r)

		gz.Close()
		zippers.Put(gz)
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// detectPasswd gets password protection settings, and authentication credentials.
func detectPasswd(url string, path string) []string {
	var tmp string

	tmp, _ = filepath.Split(url)

	b, err := ioutil.ReadFile(path + tmp + "passwd")
	if err == nil {
		tmpa := strings.Split(strings.TrimSpace(string(b)), ":")
		if len(tmpa) == 2 {
			return tmpa
		}
	}

	return []string{"err"}
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
	if conf.Log {
		fmt.Println("[WebRedir][" + r.Host + url + "] : " + r.RemoteAddr)
	}
}

// checkIntact validates the server configuration.
func checkIntact() {
	if conf.HTTP != 80 || conf.HTTPS != 443 {
		fmt.Println("[Warn] : Dynamic Serving will not work on non-standard ports!")
		if conf.HSTS.Run {
			fmt.Println("[Warn] : HSTS will not work on non-standard ports!")
			conf.HSTS.Run = false
		}
	}

	if conf.HSTS.Mix && conf.IdleTime == 0 {
		fmt.Println("[Warn] : Mixed SSL requires HTTP Keep Alive!")
		conf.HSTS.Mix = false
	}

	if conf.Cache.Run {
		_, err := os.Stat(conf.Cache.Loc)
		if err != nil {
			fmt.Println("[Warn] : Cache folder does not exist!")
			conf.Cache.Run = false
		} else if conf.Cache.Up <= 0 {
			fmt.Println("[Warn] : Cache folder cannot update too fast!")
			conf.Cache.Run = false
		}
	}

	_, err := os.Stat("html")
	if err != nil {
		fmt.Println("[Warn] : HTML folder does not exist!")
	}

	if conf.DatTime <= 4 {
		fmt.Println("[Warn] : Setting a low stream timeout may result in issues with high latency connections.")
	}

	if !conf.Cache.Run {
		conf.Cache.Loc = "norun"
	}

	if !conf.Proxy.Run {
		conf.Proxy.Loc = "norun"
	}
}

// detectPath allows dynamic content control by domain and path.
func detectPath(path string, url string, cache string, proxy string) (string, string) {
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

// loadHeaders adds headers from the server configuration to the request.
func loadHeaders(w http.ResponseWriter, exists bool, l *time.Location) {
	if conf.Name != "" {
		w.Header().Add("Server", conf.Name)
	}
	if conf.IdleTime != 0 {
		w.Header().Add("Keep-Alive", "timeout="+strconv.Itoa(conf.IdleTime))
	}
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
		w.Header().Add("Alt-Svc", `h2=":`+strconv.Itoa(conf.HTTPS)+`"; ma=`+strconv.Itoa(conf.IdleTime))
	}

	if exists {
		if conf.Pro {
			w.Header().Add("Referrer-Policy", "no-referrer")
			w.Header().Add("X-Content-Type-Options", "nosniff")
			w.Header().Add("X-Frame-Options", "sameorigin")
			w.Header().Add("X-XSS-Protection", "1; mode=block")
		}
		if conf.CachTime != 0 {
			w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
			w.Header().Set("Expires", time.Now().In(l).Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
		}
	}
}

// Create a list of files present in a directory
func dirList(w http.ResponseWriter, f os.File, urln string) {
	dirs, err := f.Readdir(-1)
	if err != nil {
		// TODO: log err.Error() to the Server.ErrorLog, once it's possible
		// for a handler to get at its Server via the ResponseWriter. See
		// Issue 12438.
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html lang=en><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><style>body,html{font-family:Verdana,sans-serif;font-size:15px;line-height:1.5;margin:0}h1,h3{font-family:Segoe UI,Arial,sans-serif;font-weight:400;margin:10px 0}h1{font-size:48px;padding:16px 0}a,h3{text-align:center}h3{font-size:24px}a,header{color:#fff}a{width:98.5%;display:inline-block;text-decoration:none;cursor:pointer;background-color:#616161;padding:8px 16px}header{background-color:#009688;padding:64px 16px 64px 32px}div{padding:.01em 16px}</style><header><h1>` + urln + `</h1></header><div style="padding:16px;"><h3>Contents of directory</h3><div style="max-width:800px;margin:auto">`))
	for _, d := range dirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		// Escape special characters from the url path
		url := url.URL{Path: name}
		w.Write([]byte("<p></p><a href=" + htmlReplacer.Replace(name) + ">" + url.String() + "</a>"))
	}
	w.Write([]byte("</div></div></div>"))
}

// wrapLoad chooses the correct handler wrappers based on server configuration.
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
			if conf.Log {
				fmt.Println("[WebHSTS][" + r.Host + r.URL.EscapedPath() + "] : " + r.RemoteAddr)
			}
		})
	}

	return tmpR, tmpH
}

// updateCache automatically updates the simple cache.
func updateCache() {
	fmt.Println("KatWeb Cache Started.")
	for {
		err := filepath.Walk(conf.Cache.Loc+"/", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println("[Cache][Warn] : Unable to get filepath info!")
				return err
			}

			if !info.IsDir() && strings.HasSuffix(path, ".txt") {
				fmt.Println("[Cache] : Updating " + strings.TrimSuffix(path, ".txt") + "...")

				b, err := ioutil.ReadFile(path)
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to read " + path + "!")
					return err
				}

				err = os.Remove(strings.TrimSuffix(path, ".txt"))
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to delete " + strings.TrimSuffix(path, ".txt") + "!")
				}

				out, err := os.Create(strings.TrimSuffix(path, ".txt"))
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to create " + strings.TrimSuffix(path, ".txt") + "!")
					return err
				}

				resp, err := client.Get(strings.TrimSpace(string(b)))
				if resp != nil {
					defer resp.Body.Close()
				}
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to download " + strings.TrimSuffix(path, ".txt") + "!")
					return err
				}

				_, err = io.Copy(out, resp.Body)
				if err != nil {
					fmt.Println("[Cache][Warn] : Unable to write " + strings.TrimSuffix(path, ".txt") + "!")
				}
			}
			return nil
		})

		if err == nil {
			fmt.Println("[Cache] : All files in cache updated!")
		} else {
			fmt.Println("[Cache][Warn] : Unable to update one of more files in the cache!")
		}
		time.Sleep(time.Duration(conf.Cache.Up) * time.Minute)
	}
}

// mainHandle handles all requests given to the http.Server
func mainHandle(w http.ResponseWriter, r *http.Request) {
	var (
		authg bool
		auth  []string
		loc   string
	)

	// Get the correct content control options for the file.
	path, url := detectPath(r.Host+"/", r.URL.EscapedPath(), conf.Cache.Loc, conf.Proxy.Loc)
	if path == conf.Proxy.Loc {
		proxy := &httputil.ReverseProxy{Director: func(r *http.Request) {
			r.URL, _ = parse(conf.Proxy.URL + strings.TrimPrefix(r.URL.EscapedPath(), "/"+conf.Proxy.Loc))
		}}
		proxy.ServeHTTP(w, r)
		if conf.Log {
			fmt.Println("[WebProxy][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}

	// Check the file's password protection options.
	finfo, err := os.Stat(path + url)
	if err == nil {
		auth = detectPasswd(url, path)
		if len(auth) > 0 && auth[0] != "err" {
			authg = true
		}
	}

	loadHeaders(w, err == nil, location)

	// Apply any required redirects.
	b, err2 := ioutil.ReadFile(path + url + ".redir")
	if err2 == nil {
		http.Redirect(w, r, strings.TrimSpace(string(b)), http.StatusPermanentRedirect)
		if conf.Log {
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
		if conf.Log {
			fmt.Println("[WebNotFound][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}
	if finfo.Name() == "passwd" {
		http.Error(w, "403 Forbidden : The request was valid, but the server is refusing action.", http.StatusForbidden)
		if conf.Log {
			fmt.Println("[WebForbid][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}
	if authg && !runAuth(w, r, auth) {
		http.Error(w, "401 Unauthorized : Authentication is required and has failed or has not yet been provided.", http.StatusUnauthorized)
		if conf.Log {
			fmt.Println("[WebUnAuth][" + r.Host + url + "] : " + r.RemoteAddr)
		}
		return
	}

	// Open the requested file
	loc = path + url
	if finfo.IsDir() {
		loc = loc + "index.html"
	}
	f, err := os.Open(loc)

	if err != nil {
		if strings.HasSuffix(loc, "index.html") {
			// If there is no index.html file for the requested path, create a list of files in the directory
			f, err := os.Open(path + url)
			if err == nil {
				dirList(w, *f, url)
				return
			}
		}
		http.Error(w, "500 Internal Server Error : An unexpected condition was encountered.", http.StatusInternalServerError)
		fmt.Println("[WebError][" + r.Host + url + "] : " + r.RemoteAddr)
		return
	}

	// Send the content requested
	finfo, err = f.Stat()
	if err != nil {
		http.Error(w, "500 Internal Server Error : An unexpected condition was encountered.", http.StatusInternalServerError)
		fmt.Println("[WebError][" + r.Host + url + "] : " + r.RemoteAddr)
		return
	}
	http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), f)
	f.Close()

	// Log the response to the console
	if conf.Log {
		if r.Method == "POST" {
			err := r.ParseForm()
			if err == nil {
				fmt.Printf("[WebForm]["+r.Host+url+"][%v] : "+r.RemoteAddr+"\n", r.PostForm)
			} else {
				fmt.Println("[WebForm][" + r.Host + url + "][Error] : " + r.RemoteAddr)
			}
		} else {
			fmt.Println("[Web][" + r.Host + url + "] : " + r.RemoteAddr)
		}
	}
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

	handleReq, handleHTTP := wrapLoad(mainHandle)

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

	// Run the server, and update the cache.
	if conf.Cache.Run {
		go updateCache()
	}
	go srvh.ListenAndServe()

	fmt.Println("KatWeb Server Started.")
	err = srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key")
	fmt.Println("[Fatal] : KatWeb was unable to start! If possible, debugging info may be printed below.")
	if err != nil {
		fmt.Println(err)
	}
}
