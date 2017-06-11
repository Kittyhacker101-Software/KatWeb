// KatWeb HTTP Server
package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
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
	HSTS     struct {
		Run bool `json:"enabled"`
		Sub bool `json:"includeSubDomains"`
		Pre bool `json:"preload"`
	} `json:"hsts"`
	Secure bool `json:"https"`
	Pro    bool `json:"protect"`
	Zip    bool `json:"gzip"`
	Dyn    struct {
		Srv  bool `json:"serving"`
		Re   bool `json:"redir"`
		Pass bool `json:"passwd"`
		Ca   bool `json:"cache"`
	} `json:"dyn"`
	No    bool `json:"silent"`
	Cache struct {
		Run bool `json:"enabled"`
		Up  int  `json:"updates"`
	} `json:"hcache"`
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

// checkIntact peforms all pre-startup checks.
func checkIntact() {
	_, err := os.Stat("html")
	if err != nil {
		fmt.Println("[Warn] : HTML folder does not exist!")
	}

	_, err = os.Stat("cache")
	if err != nil {
		fmt.Println("[Warn] : Cache folder does not exist!")
		conf.Cache.Run = false
	}

	if conf.HTTP != 80 || conf.HTTPS != 443 {
		if conf.Dyn.Srv {
			fmt.Println("[Warn] : Dynamic Serving will not work on non-standard ports!")
			conf.Dyn.Srv = false
		}
	}

	if conf.Secure {
		_, err = os.Stat("ssl/server.crt")
		_, err1 := os.Stat("ssl/server.key")
		if err != nil || err1 != nil {
			fmt.Println("[Warn] : SSL Certs do not exist!")
			conf.Secure = false
			conf.HSTS.Run = false
		}

		if conf.HSTS.Run {
			if conf.HTTPS != 443 {
				fmt.Println("[Warn] : HSTS will not work on non-standard ports!")
				conf.HSTS.Run = false
			}
		} else {
			fmt.Println("[Info] : HSTS is disabled, causing people to use HTTP by default. Enabling it is recommended.")
		}
	} else {
		if conf.HSTS.Run {
			conf.HSTS.Run = false
		}
		fmt.Println("[Info] : HTTPS is disabled, allowing hackers to intercept your connection. Enabling it is recommended.")
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
		if conf.Dyn.Ca {
			cacheB = append(cacheB, p)
			sort.Strings(cacheB)
		}
		return "html/"
	}

	if conf.Dyn.Ca {
		cacheA = append(cacheA, p)
		sort.Strings(cacheA)
	}
	return p
}

// detectPasswd checks if the folder needs to be password protected.
func detectPasswd(i os.FileInfo, p string) string {
	var tmpl string
	if i.IsDir() {
		tmpl = p

	} else {
		tmp := len(i.Name())
		tmpl = p[:len(p)-tmp]
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

// updateCache handles automatically updating the Basic HTTP Cache.
func updateCache() {
	tr := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: tr}
	for {
		err0 := filepath.Walk("cache/", func(path string, info os.FileInfo, _ error) error {
			if !info.IsDir() && len(path) > 4 && path[len(path)-4:] == ".txt" {
				if !conf.No {
					fmt.Println("[Cache][HTTP] : Updating " + path[6:len(path)-4] + "...")
				}
				b, err := ioutil.ReadFile(path)

				err1 := os.Remove("cache/" + path[6:len(path)-4])
				out, err2 := os.Create("cache/" + path[6:len(path)-4])

				resp, err3 := client.Get(strings.TrimSpace(string(b)))
				if resp != nil {
					defer resp.Body.Close()
				}

				if err != nil || err1 != nil || err2 != nil || err3 != nil {
					if !conf.No {
						fmt.Println("[Cache][Warn] : Unable to update " + path[6:len(path)-4] + "!")
					}
				} else {
					_, err = io.Copy(out, resp.Body)
					if err != nil && !conf.No {
						fmt.Println("[Cache][Warn] : Unable to update " + path[6:len(path)-4] + "!")
					}
				}
			}
			return nil
		})
		if err0 != nil && !conf.No {
			fmt.Println("[Cache][Warn] : Unable to walk filepath!")
		}
		if !conf.No {
			fmt.Println("[Cache][HTTP] : All files in HTTP Cache updated!")
		}
		time.Sleep(time.Duration(conf.Cache.Up) * time.Second)
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
		gz := gzip.NewWriter(w)
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
	if !conf.No && err != nil {
		fmt.Println("[Fatal] : Unable to read config file. Server will now stop.")
		os.Exit(1)
	}
	err = json.Unmarshal(data, &conf)
	if !conf.No && err != nil {
		fmt.Println("[Fatal] : Unable to parse config file. Server will now stop.")
		os.Exit(1)
	}

	// UTC time is required for HTTP Caching headers.
	location, err := time.LoadLocation("UTC")
	if !conf.No && err != nil {
		fmt.Println("[Fatal] : Unable to load timezones. Server will now stop.")
		os.Exit(1)
	}

	// Run checkIntact to make sure the server is setup properly.
	if !conf.No {
		checkIntact()
	}

	// mainHandle handles all HTTP Web Requests, all other handlers in here are just wrappers.
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		var (
			authg bool
			auth  []string
		)

		// Get file info, and check Dynamic Content Control settings.
		url := r.URL.EscapedPath()
		if conf.Cache.Run && len(url) > 6 && url[:6] == "/cache" {
			path = "cache/"
			url = url[6:]
		} else {
			if conf.Dyn.Srv {
				path = detectPath(r.Host + "/")
			} else {
				path = "html/"
			}
		}

		// Enable password protection of a folder if needed.
		finfo, err := os.Stat(path + url)
		if err == nil && conf.Dyn.Pass {
			tmp := detectPasswd(finfo, url)
			if tmp != "err" {
				auth = strings.Split(tmp, ":")
				if len(auth) > 1 && len(auth) < 3 {
					authg = true
				}
			}
		}

		// Check if a redirect is present, and apply the redirect if needed.
		if err != nil && conf.Dyn.Re {
			b, err := ioutil.ReadFile(path + url + ".redir")
			if err == nil {
				http.Redirect(w, r, strings.TrimSpace(string(b)), http.StatusTemporaryRedirect)
				if !conf.No {
					fmt.Println("[WebRe][" + r.Host + url + "] : " + r.RemoteAddr)
				}
				return
			}
		}

		// Add all headers from server configuration.
		w.Header().Add("Server", conf.Name)
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
		}
		if conf.Pro {
			w.Header().Add("X-Content-Type-Options", "nosniff")
			w.Header().Add("X-Frame-Options", "sameorigin")
			w.Header().Add("X-XSS-Protection", "1; mode=block")
		}
		// Add modifications timestamps, then send data.
		if err != nil {
			if !conf.No {
				fmt.Println("[Web404][" + r.Host + url + "] : " + r.RemoteAddr)
			}
			http.Error(w, "404. Not Found. The requested resource could not be found but may be available in the future.", 404)
		} else {
			if conf.CachTime != 0 {
				w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
				w.Header().Set("Expires", time.Now().In(location).Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
				w.Header().Set("Last-Modified", finfo.ModTime().In(location).Format(http.TimeFormat))
			}
			if !conf.No {
				fmt.Println("[Web][" + r.Host + url + "] : " + r.RemoteAddr)
			}

			if authg {
				if finfo.Name() == "passwd" {
					http.Error(w, "403. Forbidden. The request was valid, but the server is refusing action. The user might not have the necessary permissions for a resource.", 403)
				} else {
					// Ask for Authentication if it is required.
					if runAuth(w, r, auth) {
						http.ServeFile(w, r, path+url)
					} else {
						http.Error(w, "401. Unauthorized. Authentication is required and has failed or has not yet been provided.", 401)
					}
				}
			} else {
				http.ServeFile(w, r, path+url)
			}
		}
	}

	// Choose the correct wrappers for the handler based on server configuration.
	if conf.Zip {
		handleReq = makeGzipHandler(http.HandlerFunc(mainHandle))
	} else {
		handleReq = http.HandlerFunc(mainHandle)
	}
	if conf.Secure && conf.HSTS.Run {
		handleHTTP = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.EscapedPath(), http.StatusMovedPermanently)
			if !conf.No {
				fmt.Println("[WebHSTS][" + r.Host + r.URL.EscapedPath() + "] : " + r.RemoteAddr)
			}
		})
	} else {
		handleHTTP = handleReq
	}

	// srv handles all configuration for HTTPS.
	srv := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTPS),
		Handler:      handleReq,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}
	// srvh handles all configuration for HTTP.
	srvh := &http.Server{
		Addr:         ":" + strconv.Itoa(conf.HTTP),
		Handler:      handleHTTP,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}

	// Run HTTP Cache auto update, and start the HTTP/HTTPS servers.
	fmt.Println("KatWeb HTTP Server Started.")
	if conf.Cache.Run {
		go updateCache()
	}
	if conf.Secure {
		go srvh.ListenAndServe()
		srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key")
	} else {
		srvh.ListenAndServe()
	}

	if !conf.No {
		fmt.Println("[Fatal] : KatWeb was unable to start!")
	}
}
