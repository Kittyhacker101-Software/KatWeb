// KatWeb by kittyhacker101 - Unit Tests
// NOTE: These tests will not work properly if you have edited the contents of the "html" folder in any way!
package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"os"
	"strings"
	"testing"
)

func testHost(client *http.Client, host, url string) int {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func testHostFull(client *http.Client, host, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &http.Response{}, err
	}
	req.Host = host

	return client.Do(req)
}

func Test_Map_IO(t *testing.T) {
	data, err := ioutil.ReadFile("conf.json")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	if json.Unmarshal(data, &conf) != nil {
		t.Error("Unable to read parse testing data!")
	}

	MakeProxyMap()

	if val, ok := proxyMap.Load(conf.Proxy[0].Loc); ok {
		if !ok {
			t.Error("Could not read data from map!")
		}
		if val != conf.Proxy[0].URL {
			t.Error("Data from map is incorrect!")
		}
	}

	if val, ok := redirMap.Load(conf.Redir[0].Loc); ok {
		if !ok {
			t.Error("Could not read data from map!")
		}
		if val != conf.Redir[0].URL {
			t.Error("Data from map is incorrect!")
		}
	}
}

func Test_HTTP_Sandbox(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	if testHost(client, "localhost", server.URL+"//../") != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	if testHost(client, ".", server.URL) != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	if testHost(client, "..", server.URL) != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	if testHost(client, "ssl", server.URL) != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	server.Close()
}

func Test_HTTP_Redir(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))

	parsedURL := strings.Split(server.URL, ":")
	if len(parsedURL) != 3 {
		t.Error("Unable to parse server url!")
	}

	redirMap.Store("localhost:"+parsedURL[2]+"/redirect", "http://example.com")
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("http://localhost:" + parsedURL[2] + "/redirect")
	if err != nil {
		t.Error("Unable to connect to server!")
	}
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "http://example.com" {
		t.Error("Redirection headers not sent!")
		t.Error(resp.StatusCode)
	}
	resp.Body.Close()
}

func Test_HTTP_Virtual_Hosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	if testHost(client, "nonexistenthost", server.URL) != http.StatusOK {
		t.Error("Missing hosts are not handled correctly!")
	}

	os.Mkdir("testinghost", 0777)
	file, err := os.Create("testinghost/index.html")
	if err != nil {
		t.Error("Unable to create testing data")
	}
	file.WriteString("Hello KatWeb!")
	file.Close()

	defer os.RemoveAll("testinghost")

	resp, err := testHostFull(client, "testinghost", server.URL)
	if err != nil {
		t.Error("Unable to create request!")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	if string(body) != "Hello KatWeb!" {
		t.Error("Virtual hosts are not handled correctly!")
	}

	resp.Body.Close()
}

func Test_HTTP_Proxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))

	proxyMap.Store("testProxy", server2.URL)

	resp, err := testHostFull(client, "localhost", server.URL+"/testProxy")
	if err != nil {
		t.Error("Unable to create request!")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	if string(body) != "Hello proxy!" {
		t.Error("Reverse proxies are not handled correctly!")
	}
	
	resp.Body.Close()

	resp, err = testHostFull(client, "testProxy", server.URL)
	if err != nil {
		t.Error("Unable to create request!")
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	if string(body) != "Hello proxy!" {
		t.Error("Reverse proxies are not handled correctly!")
	}

	resp.Body.Close()
}

func Test_HTTP_Broken_Proxy(t *testing.T) {
	var err error
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	parsedURL := strings.Split(server.URL, ":")
	if len(parsedURL) != 3 {
		t.Error("Unable to parse server url!")
	}

	conf.Adv.HTTP, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	proxyMap.Store("testProxy", "htt:/exampl./%%%")

	fdata, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	resp, err := testHostFull(client, "localhost", server.URL+"/testProxy")
	if err != nil {
		t.Error("Unable to create request!")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	if string(body) != string(fdata) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	resp.Body.Close()

	resp, err = testHostFull(client, "testProxy", server.URL)
	if err != nil {
		t.Error("Unable to create request!")
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	if string(body) != string(fdata) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	resp.Body.Close()
}
