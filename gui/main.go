package main

import (
	"bufio"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/skratchdot/open-golang/open"
	"github.com/zserge/webview"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

var (
	upgrader = websocket.Upgrader{}
	srv      = &http.Server{
		Addr:    "127.0.0.1:8090",
		Handler: http.HandlerFunc(guiHandle),
	}
	katchan = make(chan string)
	katctrl = make(chan string)
	lock    bool
)

func guiHandle(w http.ResponseWriter, r *http.Request) {
	if lock {
		http.Error(w, "You do not have permission to access this resource.", http.StatusForbidden)
		return
	}
	if !strings.HasSuffix(r.URL.EscapedPath(), "/socket") {
		http.ServeFile(w, r, "index.html")
		return
	}

	lock = true
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Unable to upgrade websocket!", http.StatusInternalServerError)
		return
	}
	defer c.Close()

	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				return
			}
			katctrl <- string(message)
		}
	}()

	for {
		data := <-katchan
		c.WriteMessage(websocket.TextMessage, []byte(data))
	}

}

func manageKatWeb() {
	var (
		katweb *os.Process = nil
		katcon *bufio.Scanner
	)

	go func() {
		for {
			if katweb == nil {
				continue
			}
			for katcon.Scan() {
				katchan <- katcon.Text()
			}
		}
	}()

	for {
		data := <-katctrl
		if data == "stop" || data == "kill" || data == "restart" {
			katchan <- "clear"
			if katweb != nil {
				katweb.Signal(syscall.SIGTERM)
				katweb.Wait()
				katweb = nil
			}
		}
		if data == "start" || data == "restart" {
			c := exec.Command("./KatWeb/katweb-bin", "-root=./KatWeb")
			stdout, err := c.StdoutPipe()
			if err != nil {
				katchan <- "[Panel] : Unable to start katweb!"
				katchan <- "stop"
				katweb = nil
			}

			katcon = bufio.NewScanner(stdout)
			if c.Start() != nil {
				katchan <- "[Panel] : Unable to connect to katweb!"
				katchan <- "stop"
				katweb = nil
			}

			katweb = c.Process
			katchan <- "start"
		}
		if data == "kill" {
			os.Exit(0)
		}
		if data == "reload" {
			if katweb != nil {
				katweb.Signal(syscall.SIGHUP)
			}
		}
		if data == "folder" {
			open.Run("./KatWeb/")
		}
		if data == "config" {
			open.Run("./KatWeb/conf.json")
		}
	}
}

func main() {
	go func() {
		if srv.ListenAndServe() != nil {
			fmt.Println("Unable to start GUI backend!")
			os.Exit(1)
		}
	}()
	go func() {
		time.Sleep(1 * time.Second)
		katctrl <- "start"
		webview.New(webview.Settings{
			Title:     "KatWeb Control Panel",
			URL:       "http://localhost:8090",
			Width:     450,
			Height:    438,
			Resizable: true,
			Debug:     true,
		}).Run()
		katctrl <- "kill"
	}()
	manageKatWeb()
}
