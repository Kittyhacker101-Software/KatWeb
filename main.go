// KatWeb by kittyhacker101
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
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

func director(r *http.Request) {
	u := r.URL.EscapedPath()

	/* This never returns an error for some reason, so why bother handling it?
	Not to mention, there's not any real way to handle an error here anyways. */
	r.URL, _ = url.Parse(conf.Proxy.URL + strings.TrimPrefix(u, "/"+conf.Proxy.Loc))
}

var (
	conf Conf

	// tlsc provides a SSL config that is more secure than Golang's default.
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
			/* Note : Comment the bottom two ciphers and uncomment the middle two, for a 100% score in SSL Labs.
			If you enable this, the server will not start unless you disable HTTP/2 in srv. */
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			/* tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, */
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
)

// checkIntact checks to make sure all folders exist and that the server configuration is valid.
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
		// Note : You will want to disable HSTS Mixed if you disable HTTP/2.
		w.Header().Add("Alt-Svc", `h2=":`+strconv.Itoa(conf.HTTPS)+`"; ma=`+strconv.Itoa(conf.IdleTime))
	}

	if exists {
		if conf.Pro {
			/* This code will prevent other sites from directly pulling your content.
			Might cause issues if your site spans multiple domains. */
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

// wrapLoad chooses the correct wrappers based on server configuration.
func wrapLoad(origin http.HandlerFunc) (http.Handler, http.Handler) {
	tmpR := origin
	if conf.Zip.Run {
		tmpR = MakeGzipHandler(origin, conf.Zip.Lvl)
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

// updateCache automatically updates the Basic HTTP Cache.
func updateCache() {
	fmt.Println("KatWeb Cache Started.")

	tr := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   time.Duration(conf.IdleTime) * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(conf.DatTime) * time.Second,
	}

	for {
		err := filepath.Walk(conf.Cache.Loc+"/", func(path string, info os.FileInfo, err error) error {
			if err != nil {
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

		if err != nil {
			fmt.Println("[Cache][Warn] : Unable to walk filepath!")
		} else {
			fmt.Println("[Cache][HTTP] : All files in HTTP Cache updated!")
		}
		time.Sleep(time.Duration(conf.Cache.Up) * time.Minute)
	}
}

// The main function handles startup and webserver logic.
func main() {
	fmt.Println("Loading KatWeb...")

	// Load the config file, and then parse it into the conf struct. Then, peform additional checks on it.
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

	// mainHandle handles all HTTP Web Requests sent to KatWeb.
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		var (
			authg bool
			auth  []string
		)

		// Get file info, and check Dynamic Content Control settings.
		path, url := DetectPath(r.Host+"/", r.URL.EscapedPath())
		if path == conf.Proxy.Loc {
			// No additional headers are added, we will depend on the proxied server to provide those.
			proxy := &httputil.ReverseProxy{Director: director}
			proxy.ServeHTTP(w, r)
			fmt.Println("[WebProxy][" + r.Host + url + "] : " + r.RemoteAddr)
			return
		}

		// Enable password protection of a folder if needed.
		finfo, err := os.Stat(path + url)
		if err == nil {
			auth = DetectPasswd(finfo, url, path)
			if auth[0] != "err" {
				authg = true
			}
		}

		loadHeaders(w, err == nil, location)

		// Check if a redirect is present, and apply the redirect if needed.
		if err != nil {
			b, err := ioutil.ReadFile(path + url + ".redir")
			if err == nil {
				/* These redirects are set as permanent, it's rare for server-side temporary redirects to be set.
				If you wanted a temporary redirect, then why not just use HTML for it instead? */
				http.Redirect(w, r, strings.TrimSpace(string(b)), http.StatusPermanentRedirect)
				fmt.Println("[Web301][" + r.Host + url + "] : " + r.RemoteAddr)
				return
			}
		}

		/* Add file headers, then send data. Add HTTP errors if required.
		I may consider allowing changing of the error text in the future, but it's unlikely to be used. */
		if err != nil {
			http.Error(w, "404 Not Found : The requested resource could not be found but may be available in the future.", 404)
			fmt.Println("[Web404][" + r.Host + url + "] : " + r.RemoteAddr)
		} else {
			if authg {
				if finfo.Name() == "passwd" {
					http.Error(w, "403 Forbidden : The request was valid, but the server is refusing action. The user might not have the necessary permissions for a resource.", 403)
					fmt.Println("[Web403][" + r.Host + url + "] : " + r.RemoteAddr)
				} else if RunAuth(w, r, auth) {
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

	handleReq, handleHTTP := wrapLoad(mainHandle)

	// srv handles all configuration for HTTPS.
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTPS),
		Handler:      handleReq,
		TLSConfig:    tlsc,
		ReadTimeout:  time.Duration(conf.DatTime) * time.Second,
		WriteTimeout: time.Duration(conf.DatTime*2) * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
		/* Uncomment this snippet of code if you wish to disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0) */
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
	go srvh.ListenAndServe()

	fmt.Println("KatWeb Server Started.")
	err = srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key")
	fmt.Println("[Fatal] : KatWeb was unable to start! If possible, debugging info may be printed below.")
	if err != nil {
		fmt.Println(err)
	}
}
