// KatWeb by kittyhacker101 - Unit Tests
// NOTE: These tests will not work properly if you have edited the contents of the "html" folder in any way!
package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
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
	return resp.StatusCode
}

func testHostFull(client *http.Client, host, url string) (*http.Response, error) {
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &http.Response{}, err
	}
	req.Host = host

	return client.Do(req)
}

func testHostCompare(client *http.Client, host, url, expect string) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	resp.Body.Close()

	return string(body) != expect
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

func Test_HTTP_Redirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	parsedURL := strings.Split(server.URL, ":")
	if len(parsedURL) != 3 {
		t.Error("Unable to parse server url!")
	}

	redirMap.Store("localhost:"+parsedURL[2]+"/redirect", "http://example.com")

	resp, err := testHostFull(client, "localhost", "http://localhost:"+parsedURL[2]+"/redirect")
	if err != nil {
		t.Error("Unable to connect to server!")
	}
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "http://example.com" {
		t.Error("Redirection headers not sent!")
	}

	resp, err = testHostFull(client, "localhost", server.URL+"/index.html")
	if err != nil {
		t.Error("Unable to connect to server!")
	}
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "./" {
		t.Error("Redirection headers not sent!")
	}
}

func Test_HTTP_File_Serving(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	fdata, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	if testHostCompare(client, "localhost", server.URL, string(fdata)) {
		t.Error("File serving is not handled correctly!")
	}
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

	if testHostCompare(client, "testinghost", server.URL, "Hello KatWeb!") {
		t.Error("Virtual hosts are not handled correctly!")
	}
}

func Test_HTTP_Proxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))

	proxyMap.Store("testProxy", server2.URL)

	if testHostCompare(client, "localhost", server.URL+"/testProxy", "Hello proxy!") {
		t.Error("Virtual hosts are not handled correctly!")
	}

	if testHostCompare(client, "testProxy", server.URL, "Hello proxy!") {
		t.Error("Virtual hosts are not handled correctly!")
	}
}

func Test_HTTP_Proxy_Broken(t *testing.T) {
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

	if testHostCompare(client, "localhost", server.URL+"/testProxy", string(fdata)) {
		t.Error("Virtual hosts are not handled correctly!")
	}

	if testHostCompare(client, "testProxy", server.URL, string(fdata)) {
		t.Error("Virtual hosts are not handled correctly!")
	}
}

func Test_HTTPS_Proxy_Broken(t *testing.T) {
	var err error
	server := httptest.NewTLSServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	conf.HSTS = true
	tlsp.InsecureSkipVerify = true

	parsedURL := strings.Split(server.URL, ":")
	if len(parsedURL) != 3 {
		t.Error("Unable to parse server url!")
	}

	conf.Adv.HTTPS, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	proxyMap.Store("testProxy", "htt:/exampl./%%%")

	fdata, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	if testHostCompare(client, "localhost", server.URL+"/testProxy", string(fdata)) {
		t.Error("Virtual hosts are not handled correctly!")
	}

	if testHostCompare(client, "testProxy", server.URL, string(fdata)) {
		t.Error("Virtual hosts are not handled correctly!")
	}
}
