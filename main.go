package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/NYTimes/gziphandler"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

// Config file structure
type Conf struct {
	IdleTime int `json:"keepAliveTimeout"`
	CachTime int `json:"cachingTimeout"`
	HSTS     struct {
		Run bool `json:"enabled"`
		Sub bool `json:"includeSubDomains"`
		Pre bool `json:"preload"`
	} `json:"hsts"`
	Secure bool   `json:"https"`
	BSniff bool   `json:"nosniff"`
	IFrame bool   `json:"sameorigin"`
	Zip    bool   `json:"gzip"`
	Dyn    bool   `json:"dynamicServing"`
	DynCa  bool   `json:"cacheStruct"`
	No     bool   `json:"silent"`
	Name   string `json:"name"`
}

var (
	conf   Conf
	cacheA = []string{"html/"}
	cacheB = []string{"ssl/", "error/"}
)

// Check if path exists for domain, and use it instead of default if it does.
func detectPath(p string) string {
	// Cache stuff into a list, so that we use the hard disk less
	if conf.DynCa {
		fmt.Println(cacheA)
		fmt.Println(cacheB)

		loc := sort.SearchStrings(cacheA, p)
		if loc < len(cacheA) && cacheA[loc] == p {
			return p
		}
		loc = sort.SearchStrings(cacheB, p)
		if loc < len(cacheB) && cacheB[loc] == p {
			return "html/"
		}
	} else {
		if p == "ssl/" || p == "error/" || p == "html/" {
			return "html/"
		}
	}

	// If it's not in the cache, check the hard disk, and add it to the cache
	_, err := os.Stat(p)
	if err != nil {
		if conf.DynCa {
			cacheB = append(cacheB, p)
			sort.Strings(cacheB)
		}
		return "html/"
	} else {
		if conf.DynCa {
			cacheA = append(cacheA, p)
			sort.Strings(cacheA)
		}
		return p
	}
}

func main() {
	// Load and parse config files
	fmt.Println("Loading config files...")
	data, err := ioutil.ReadFile("./conf.json")
	if !conf.No && err != nil {
		fmt.Println("Unable to load config file. Server will now stop.")
		os.Exit(0)
	}
	json.Unmarshal(data, &conf)

	fmt.Println("Loading server...")

	// We must use the UTC format when using .Format(http.TimeFormat) on the time.
	location, err := time.LoadLocation("UTC")
	if !conf.No && err != nil {
		fmt.Println("Unable to load timezones. Server will now stop.")
		os.Exit(0)
	}

	// This handles all web requests
	mainHandle := func(w http.ResponseWriter, r *http.Request) {

		// Check path and file info
		var path string
		if conf.Dyn {
			path = detectPath(r.Host + "/")
		} else {
			path = "html/"
		}
		finfo, err := os.Stat(path + r.URL.Path[1:])

		// Add important headers
		w.Header().Add("Server", conf.Name)
		w.Header().Add("Keep-Alive", "timeout="+strconv.Itoa(conf.IdleTime))
		if conf.CachTime != 0 {
			w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(3600*conf.CachTime)+", public, stale-while-revalidate=3600")
			w.Header().Set("Expires", time.Now().In(location).Add(time.Duration(conf.CachTime)*time.Hour).Format(http.TimeFormat))
		}
		if conf.HSTS.Run {
			if conf.HSTS.Sub {
				if conf.HSTS.Pre {
					w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains;preload")
				} else {
					w.Header().Add("Strict-Transport-Security", "max-age=31536000;includeSubDomains")
				}
			} else {
				// Preload requires includeSubDomains for some reason, idk why.
				w.Header().Add("Strict-Transport-Security", "max-age=31536000")
			}
		}
		if conf.BSniff {
			w.Header().Add("X-Content-Type-Options", "nosniff")
		}
		if conf.IFrame {
			w.Header().Add("X-Frame-Options", "sameorigin")
		}
		// Check if file exists, and if it does then add modification timestamp. Then send file.
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Last-Modified", time.Now().In(location).Format(http.TimeFormat))
			if !conf.No {
				fmt.Println(r.RemoteAddr + " - 404 Error")
			}
			http.ServeFile(w, r, "error/NotFound.html")
		} else {
			w.Header().Set("Last-Modified", finfo.ModTime().In(location).Format(http.TimeFormat))
			if !conf.No {
				fmt.Println(r.RemoteAddr + " - " + r.Host + r.URL.Path)
			}
			http.ServeFile(w, r, path+r.URL.Path[1:])
		}
	}

	// HTTP Compression!!!
	var handleReq http.Handler
	if conf.Zip {
		handleReq = gziphandler.GzipHandler(http.HandlerFunc(mainHandle))
	} else {
		handleReq = http.HandlerFunc(mainHandle)
	}

	// Config for HTTPS, basicly making things a lil more secure
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}
	// Config for HTTPS Server
	srv := &http.Server{
		Addr:         ":443",
		Handler:      handleReq,
		TLSConfig:    cfg,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}
	// Config for HTTP Server, redirects to HTTPS
	srvh := &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.EscapedPath(), http.StatusMovedPermanently)
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}
	// Secondary config for HTTP Server
	srvn := &http.Server{
		Addr:         ":80",
		Handler:      handleReq,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  time.Duration(conf.IdleTime) * time.Second,
	}

	// This code actually starts the servers.
	fmt.Println("KatWeb HTTP Server Started.")
	if conf.Secure {
		// We use a Goroutine because the HTTP and HTTPS servers need to run at the same time.
		// If browsers defaulted to HTTPS, this wouldn't be needed.
		if conf.HSTS.Run {
			// HTTP Server which redirects to HTTPS
			go srvh.ListenAndServe()
		} else {
			// Serves the same content as HTTPS, but unencrypted.
			go srvn.ListenAndServe()
		}
		srv.ListenAndServeTLS("ssl/server.crt", "ssl/server.key")
	} else {
		srvn.ListenAndServe()
	}
}
