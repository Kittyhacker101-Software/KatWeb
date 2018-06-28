package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/grafov/bcast"
	"github.com/shirou/gopsutil/process"
	"github.com/skratchdot/open-golang/open"
	"github.com/zserge/webview"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
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
	load    bool
	katstat bool
	guicast = bcast.NewGroup()
	noui    = flag.Bool("headless", false, "Launch only the web GUI, don't launch the webview interface.")
)

func guiHandle(w http.ResponseWriter, r *http.Request) {
	load = true
	if !strings.HasSuffix(r.URL.EscapedPath(), "/socket") {
		http.ServeFile(w, r, "index.html")
		return
	}

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

	if katstat {
		c.WriteMessage(websocket.TextMessage, []byte("start"))
	} else {
		c.WriteMessage(websocket.TextMessage, []byte("stop"))
	}

	member := guicast.Join()
	for {
		data := member.Recv().(string)
		c.WriteMessage(websocket.TextMessage, []byte(data))
	}

}

func floatToString(i float64) string {
	return strconv.FormatFloat(math.Round(i*10)/10, 'f', -1, 64)
}

func manageKatWeb() {
	var (
		katweb *os.Process = nil
		katcon *bufio.Scanner
	)

	go func() {
		for {
			if !katstat {
				continue
			}
			for katcon.Scan() {
				katchan <- katcon.Text()
			}
		}
	}()

	go func() {
		for {
			if !katstat {
				continue
			}

			proc, err := process.NewProcess(int32(katweb.Pid))
			if err != nil {
				continue
			}

			cpu, err := proc.CPUPercent()
			if err != nil {
				continue
			}

			mem, err := proc.MemoryInfo()
			if err != nil {
				continue
			}

			katchan <- floatToString(cpu) + "% Avg CPU | " + floatToString(float64(mem.RSS)/1000000) + "mb RAM | PID : " + strconv.Itoa(katweb.Pid)
			time.Sleep(1 * time.Second)
		}
	}()

	for {
		data := <-katctrl
		if data == "stop" || data == "kill" || data == "restart" {
			katchan <- "clear"
			if katstat {
				katweb.Signal(syscall.SIGTERM)
				katweb.Wait()
				katstat = false
			}
		}
		if data == "start" || data == "restart" {
			c := exec.Command("./KatWeb/katweb-bin", "-root=./KatWeb")
			stdout, err := c.StdoutPipe()
			if err != nil {
				katchan <- "[Panel] : Unable to start katweb!"
				katchan <- "stop"
				katstat = false
				continue
			}

			katcon = bufio.NewScanner(stdout)
			if c.Start() != nil {
				katchan <- "[Panel] : Unable to connect to katweb!"
				katchan <- "stop"
				katstat = false
				continue
			}

			katweb = c.Process
			katchan <- "start"
			katchan <- "[Panel] : KatWeb started with pid " + strconv.Itoa(katweb.Pid) + "."
			katstat = true
			go func() {
				katweb.Wait()
				katchan <- "stop"
				katchan <- "[Panel] : KatWeb has stopped running!"
				katstat = false
			}()
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
		flag.Parse()
		katctrl <- "start"
		if *noui {
			c := make(chan os.Signal, 2)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
		} else {
			webview.New(webview.Settings{
				Title:     "KatWeb Control Panel",
				URL:       "http://localhost:8090",
				Width:     448,
				Height:    436,
				Resizable: true,
				Debug:     true,
			}).Run()
		}
		katctrl <- "kill"
	}()
	go guicast.Broadcast(0)
	go func() {
		time.Sleep(1 * time.Second)
		for {
			val := <-katchan
			guicast.Send(val)
			//fmt.Println(val)
		}
	}()
	manageKatWeb()
}
