// KatWeb by kittyhacker101 - KatWeb Control Panel
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/grafov/bcast"
	"github.com/shirou/gopsutil/process"
	"github.com/skratchdot/open-golang/open"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const katloc = ".."

var (
	upgrader = websocket.Upgrader{}
	katchan  = make(chan string)
	katctrl  = make(chan string)
	load     bool
	katstat  bool
	guicast  = bcast.NewGroup()
	bind     = flag.String("bind", "127.0.0.1:8090", `Port and IP to bind to.`)
	exlog    = flag.Bool("extLog", false, `Use the combined logging format, instead of the simplified logging.`)
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
		var message []byte
		for {
			_, message, err = c.ReadMessage()
			if err != nil {
				return
			}
			katctrl <- string(message)
		}
	}()

	if katstat {
		err = c.WriteMessage(websocket.TextMessage, []byte("start"))
	} else {
		err = c.WriteMessage(websocket.TextMessage, []byte("stop"))
	}
	if err != nil {
		return
	}

	member := guicast.Join()
	for {
		data := member.Recv().(string)
		if c.WriteMessage(websocket.TextMessage, []byte(data)) != nil {
			return
		}
	}

}

func floatToString(i float64) string {
	return strconv.FormatFloat(math.Round(i*10)/10, 'f', -1, 64)
}

func manageKatWeb() {
	var (
		katweb  *os.Process
		katcon  *bufio.Scanner
		logType = "simple"
	)
	if *exlog {
		logType = "combinedvhost"
	}

	go func() {
		for {
			if !katstat {
				time.Sleep(1 * time.Second)
				continue
			}
			for katcon.Scan() {
				katchan <- "^" + katcon.Text()
			}
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
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
		}
	}()

	for {
		data := <-katctrl
		if data == "stop" || data == "kill" || data == "restart" {
			if katstat {
				katweb.Signal(syscall.SIGTERM)
				katweb.Wait()
				katstat = false
			}
			time.Sleep(250 * time.Millisecond)
		}
		if data == "start" || data == "restart" {
			os := runtime.GOARCH
			if os == "386" {
				os = "i386"
			}

			c := exec.Command(katloc+"/katweb-"+runtime.GOOS+"-"+os, "-root="+katloc, "-logType="+logType)
			stdout, err := c.StdoutPipe()
			if err != nil {
				katchan <- "^[Panel] : Unable to start katweb!"
				katchan <- "stop"
				katstat = false
				continue
			}

			katcon = bufio.NewScanner(stdout)
			if c.Start() != nil {
				katchan <- "^[Panel] : Unable to connect to katweb!"
				katchan <- "stop"
				katstat = false
				continue
			}

			katweb = c.Process
			katchan <- "start"
			katchan <- "^[Panel] : KatWeb started with pid " + strconv.Itoa(katweb.Pid) + "."
			katstat = true
			go func() {
				katweb.Wait()
				katchan <- "stop"
				katchan <- "^[Panel] : KatWeb has stopped running!"
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
			abs, err := filepath.Abs(filepath.Dir(katloc + "/"))
			if err != nil {
				katchan <- "^[Panel] : Unable to get KatWeb's working directory!"
			} else {
				katchan <- "^[Panel] : KatWeb's working directory is " + abs
			}
			open.Start(katloc + "/")
		}
		if data == "config" {
			open.Start(katloc + "/conf.json")
		}
	}
}

func main() {
	flag.Parse()
	go func() {
		srv := &http.Server{
			Addr:    *bind,
			Handler: http.HandlerFunc(guiHandle),
		}
		if srv.ListenAndServe() != nil {
			fmt.Println("Unable to start GUI backend!")
			os.Exit(1)
		}
	}()
	go func() {
		katctrl <- "start"
		fmt.Println("Control panel started on port " + *bind)
		open.Start("http://" + *bind)
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		katctrl <- "kill"
	}()
	go guicast.Broadcast(0)
	go func() {
		time.Sleep(1 * time.Second)
		for {
			val := <-katchan
			guicast.Send(val)
		}
	}()
	manageKatWeb()
}
