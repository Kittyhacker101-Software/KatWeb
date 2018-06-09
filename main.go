// KatWeb by kittyhacker101
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
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

const currentVersion = "v1.10.0"

var (
	conf Conf

	rootl = flag.String("root", ".", "Root folder location")
	svrh  = flag.String("serverName", "KatWeb", `String set in the "server" HTTP header.`)
	noup  = flag.Bool("ignoreUpdates", false, "Disable checking if KatWeb is up to date.")
	vers  = flag.Bool("version", false, "View info about this KatWeb binary.")
)

func main() {
	flag.Parse()
	if *vers {
		fmt.Println("KatWeb " + currentVersion + ", built for " + runtime.GOOS + "-" + runtime.GOARCH + ", using " + runtime.Compiler + " compiler.")
		return
	}

	fmt.Println("[Info] : Loading KatWeb...")
	os.Chdir(*rootl)

	if !*noup {
		go fmt.Print(CheckUpdate(currentVersion))
	}

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
		MaxHeaderBytes:    8192,
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
		MaxHeaderBytes:    8192,
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
