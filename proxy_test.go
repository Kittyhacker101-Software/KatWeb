// KatWeb by kittyhacker101 - Proxy Unit Tests
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"crypto/tls"
	"testing"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func testingWSServer(w http.ResponseWriter, r *http.Request, output string) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		if string(message) != "ping" {
			break
		}
		err = c.WriteMessage(mt, []byte(output))
		if err != nil {
			break
		}
	}
}

func Test_ProxyRequest_HTTP(t *testing.T) {
	var err error

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prox, _ := GetProxy(r)
		if prox != "" {
			ProxyRequest(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello client!`))
	}))
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))

	proxyMap.Store("testProxy", server2.URL)
	proxySort = append(proxySort, "testProxy")
	proxyMap.Store("testProxy2", "htt:/exampl./%%%")
	proxySort = append(proxySort, "testProxy2")
	proxyMap.Store("testProxy3", "http://127.0.0.1:65535")
	proxySort = append(proxySort, "testProxy3")

	parsedURL := strings.Split(server.URL, ":")
	conf.Adv.HTTP, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	resp, err := server.Client().Get(server.URL + "/testProxy")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello proxy!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Host = "testProxy"

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello proxy!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello client!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL + "/testProxy2")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello client!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		Print(buf.String())
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL + "/testProxy3")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 502 {
		Print(buf.String())
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp.Body.Close()
}

func Test_ProxyRequest_HTTPS(t *testing.T) {
	var err error

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prox, _ := GetProxy(r)
		if prox != "" {
			ProxyRequest(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello client!`))
	}))
	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))

	proxyMap.Store("testProxy", server2.URL)
	proxySort = append(proxySort, "testProxy")
	proxyMap.Store("testProxy2", "htt:/exampl./%%%")
	proxySort = append(proxySort, "testProxy2")
	proxyMap.Store("testProxy3", "https://127.0.0.1:65535")
	proxySort = append(proxySort, "testProxy3")

	parsedURL := strings.Split(server.URL, ":")
	conf.HSTS = true
	conf.Adv.HTTPS, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	resp, err := server.Client().Get(server.URL + "/testProxy")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello proxy!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Host = "testProxy"

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello proxy!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello client!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL + "/testProxy2")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "Hello client!" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		Print(buf.String())
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp, err = server.Client().Get(server.URL + "/testProxy3")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 502 {
		Print(buf.String())
		t.Fatal("GetProxy is not functioning properly!")
	}

	resp.Body.Close()
}

func Test_ProxyRequest_WS(t *testing.T) {
	var err error

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prox, _ := GetProxy(r)
		if prox != "" {
			ProxyRequest(w, r)
			return
		}

		testingWSServer(w, r, "poing")
	}))
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testingWSServer(w, r, "pong")
	}))

	proxyMap.Store("testProxy", server2.URL)
	proxySort = append(proxySort, "testProxy")
	proxyMap.Store("testProxy2", "htt:/exampl./%%%")
	proxySort = append(proxySort, "testProxy2")

	parsedURL := strings.Split(server.URL, ":")
	conf.HSTS = false
	conf.Adv.HTTP, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	c, _, err := websocket.DefaultDialer.Dial("ws://localhost:"+parsedURL[2]+"/testProxy", nil)
	if err != nil {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	c.WriteMessage(websocket.TextMessage, []byte("ping"))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			t.Fatal("ProxyRequest is not functioning properly!")
			return
		}
		if string(message) != "pong" {
			t.Fatal("ProxyRequest is not functioning properly!")
		} else {
			c.Close()
			break
		}
	}

	c, _, err = websocket.DefaultDialer.Dial("ws://localhost:"+parsedURL[2]+"/testProxy2", nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	c.WriteMessage(websocket.TextMessage, []byte("ping"))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			t.Fatal("Unable to get testing data!")
			return
		}
		if string(message) != "poing" {
			t.Fatal("GetProxy is not functioning properly!")
		} else {
			c.Close()
			break
		}
	}
}

func Test_ProxyRequest_WSS(t *testing.T) {
	var err error

	wsdialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prox, _ := GetProxy(r)
		if prox != "" {
			ProxyRequest(w, r)
			return
		}

		testingWSServer(w, r, "poing")
	}))
	server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testingWSServer(w, r, "pong")
	}))

	proxyMap.Store("testProxy", server2.URL)
	proxySort = append(proxySort, "testProxy")
	proxyMap.Store("testProxy2", "htt:/exampl./%%%")
	proxySort = append(proxySort, "testProxy2")

	parsedURL := strings.Split(server.URL, ":")
	conf.HSTS = true
	conf.Adv.HTTPS, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	c, _, err := wsdialer.Dial("wss://localhost:"+parsedURL[2]+"/testProxy", nil)
	if err != nil {
		t.Fatal("ProxyRequest is not functioning properly!")
	}

	c.WriteMessage(websocket.TextMessage, []byte("ping"))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			t.Fatal("ProxyRequest is not functioning properly!")
			return
		}
		if string(message) != "pong" {
			t.Fatal("ProxyRequest is not functioning properly!")
		} else {
			c.Close()
			break
		}
	}

	c, _, err = wsdialer.Dial("wss://localhost:"+parsedURL[2]+"/testProxy2", nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	c.WriteMessage(websocket.TextMessage, []byte("ping"))

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			t.Fatal("Unable to get testing data!")
			return
		}
		if string(message) != "poing" {
			t.Fatal("GetProxy is not functioning properly!")
		} else {
			c.Close()
			break
		}
	}
}
