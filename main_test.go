// KatWeb by kittyhacker101 - Unit Tests
// NOTE: These tests have many points of failure. These tests are written only for the purpose of telling if something has gone wrong, not where the issue is located.
package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/debug"
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
	resp.Body.Close()
	return resp.StatusCode
}

func testHostFull(client *http.Client, host, url string) (*http.Response, error) {
	client.Transport.(*http.Transport).DisableCompression = true
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

func testHostAuth(client *http.Client, username, password, url string) (*http.Response, error) {
	client.Transport.(*http.Transport).DisableCompression = true

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &http.Response{}, err
	}
	req.SetBasicAuth(username, password)

	return client.Do(req)
}

func testHostCompare(client *http.Client, host, url, expect string) bool {
	client.Transport.(*http.Transport).DisableCompression = true

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

	return string(body) == expect
}

func fileToString(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func clearGarbage() {
	debug.SetGCPercent(720)
	runtime.GC()
}

// ----- Benchmarks -----

func Benchmark_Request_Ideal(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))
	client := server.Client()
	conf.Adv.Dev = false

	client.Transport = &http.Transport{
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
	}
	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL)
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		io.Copy(ioutil.Discard, resp.Body)
	}
	server.Close()
}

func Benchmark_Request_Missing(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()
	conf.Adv.Dev = false

	client.Transport = &http.Transport{
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
	}
	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL+"/nonexistentfile")
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		io.Copy(ioutil.Discard, resp.Body)
	}
	server.Close()
}

func Benchmark_Request_Index(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()
	conf.Adv.Dev = false

	client.Transport = &http.Transport{
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
	}
	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL)
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		io.Copy(ioutil.Discard, resp.Body)
	}
	server.Close()
}

func Benchmark_Request_Proxy(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))
	client := server.Client()
	conf.Adv.Dev = false
	proxyMap.Store("benchProxy", server2.URL)
	proxySort = append(proxySort, "benchProxy")

	client.Transport = &http.Transport{
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
	}
	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL+"/benchProxy")
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		io.Copy(ioutil.Discard, resp.Body)
	}
	server.Close()
	server2.Close()
}

func Benchmark_Request_NoKeepAlive_Ideal(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))
	client := server.Client()
	conf.Adv.Dev = false
	conf.Adv.Pro = false

	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL)
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		resp.Body.Close()
	}
	server.Close()
}

func Benchmark_Request_NoKeepAlive_Missing(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()
	conf.Adv.Dev = false

	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL+"/nonexistentfile")
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		resp.Body.Close()
	}
	server.Close()
}

func Benchmark_Request_NoKeepAlive_Index(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()
	conf.Adv.Dev = false

	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL)
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		resp.Body.Close()
	}
	server.Close()
}

func Benchmark_Request_NoKeepAlive_Proxy(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))
	client := server.Client()
	conf.Adv.Dev = false
	proxyMap.Store("benchProxy", server2.URL)
	proxySort = append(proxySort, "benchProxy")

	clearGarbage()
	for n := 0; n < b.N; n++ {
		resp, err := testHostFull(client, "localhost", server.URL+"/benchProxy")
		if err != nil {
			b.Error("Unable to request server!")
			return
		}
		resp.Body.Close()
	}
	server.Close()
	server2.Close()
}

// ----- Unit Tests -----

func TestMain(m *testing.M) {
	data, err := ioutil.ReadFile("conf.json")
	if err != nil {
		os.Exit(1)
	}

	if json.Unmarshal(data, &conf) != nil {
		os.Exit(1)
	}

	MakeProxyMap()
	conf.Adv.Dev = false
	conf.No = []string{"hiddenhost"}

	m.Run()
}

func Test_Updater(t *testing.T) {
	up, vers, err := CheckUpdate("v1.0")
	if err != nil {
		t.Error("Unable to run updater!")
	}

	if up != 2 {
		t.Error("Updater is not comparing version numbers correctly!")
	}

	latest, err := strconv.ParseFloat(vers[3:], 32)
	if err != nil {
		t.Error("Updater is not providing correct version numbers!")
	}

	latest = latest + 0.2
	up, _, err = CheckUpdate("v1." + strconv.FormatFloat(latest, 'f', -1, 32))
	if err != nil {
		t.Error("Unable to run updater!")
	}

	if up != -1 {
		t.Error("Updater is not comparing version numbers correctly!")
	}

	latest = latest - 0.3
	up, _, err = CheckUpdate("v1." + strconv.FormatFloat(latest, 'f', -1, 32))
	if err != nil {
		t.Error("Unable to run updater!")
	}

	if !(up == 1 || up == 2) {
		t.Error("Updater is not comparing version numbers correctly!")
	}
}

func Test_Address_Trim(t *testing.T) {
	if trimPort("") != "html" {
		t.Error("Address trimming is not working correctly!")
	}
	if trimPort("localhost") != "localhost" {
		t.Error("Address trimming is not working correctly!")
	}
	if trimPort("localhost:8080") != "localhost" {
		t.Error("Address trimming is not working correctly!")
	}
	if trimPort("127.0.0.1") != "127.0.0.1" {
		t.Error("IPv4 address trimming is not working correctly!")
	}
	if trimPort("127.0.0.1:8080") != "127.0.0.1" {
		t.Error("IPv4 address trimming is not working correctly!")
	}
	if trimPort("[::1]") != "[::1]" {
		t.Error("IPv6 address trimming is not working correctly!")
	}
	if trimPort("[::1]:8080") != "[::1]" {
		t.Error("IPv6 address trimming is not working correctly!")
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
	redirSort = append(redirSort, "localhost:"+parsedURL[2]+"/redirect")

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

	server.Close()
}

func Test_HTTP_File_Serving(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	if !testHostCompare(client, "localhost", server.URL, fileToString("html/index.html")) {
		t.Error("File serving is not handled correctly!")
	}

	if !testHostCompare(client, "nonexistenthost", server.URL, fileToString("html/index.html")) {
		t.Error("Missing virtual hosts are not handled correctly!")
	}

	os.Mkdir("hiddenhost", 0777)
	defer os.RemoveAll("hiddenhost")
	if !testHostCompare(client, "hiddenhost", server.URL, fileToString("html/index.html")) {
		t.Error("File serving is not handled correctly!")
	}

	os.Mkdir("testinghost", 0777)
	file, err := os.Create("testinghost/index.html")
	if err != nil {
		t.Error("Unable to create testing data")
	}
	file.WriteString("Hello KatWeb!")
	file.Close()

	defer os.RemoveAll("testinghost")

	if !testHostCompare(client, "testinghost", server.URL, "Hello KatWeb!") {
		t.Error("Virtual hosts are not handled correctly!")
	}

	if testHost(client, "localhost", server.URL+"/nonexistentfile") != http.StatusNotFound {
		t.Error("Missing files are not handled correctly!")
	}

	os.Remove("testinghost/index.html")

	if testHost(client, "testinghost", server.URL) != http.StatusOK {
		t.Error("Folders with no index are not handled correctly!")
	}

	server.Close()
}

func Test_HTTP_Proxy(t *testing.T) {
	var err error
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`Hello proxy!`))
	}))

	proxyMap.Store("testProxy", server2.URL)
	proxySort = append(proxySort, "testProxy")
	proxyMap.Store("testProxy2", "htt:/exampl./%%%")
	proxySort = append(proxySort, "testProxy2")

	parsedURL := strings.Split(server.URL, ":")
	conf.Adv.HTTP, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	if !testHostCompare(client, "localhost", server.URL+"/testProxy", "Hello proxy!") {
		t.Error("Reverse proxies are not handled correctly!")
	}

	if !testHostCompare(client, "testProxy", server.URL, "Hello proxy!") {
		t.Error("Reverse proxies are not handled correctly!")
	}

	if !testHostCompare(client, "localhost", server.URL+"/testProxy2", fileToString("html/index.html")) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	if !testHostCompare(client, "testProxy2", server.URL, fileToString("html/index.html")) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	server.Close()
	server2.Close()
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
	proxySort = append(proxySort, "testProxy")

	if !testHostCompare(client, "localhost", server.URL+"/testProxy", fileToString("html/index.html")) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	if !testHostCompare(client, "testProxy", server.URL, fileToString("html/index.html")) {
		t.Error("Reverse proxies are not handled correctly!")
	}

	server.Close()
}

func Test_HTTP_Auth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(mainHandle))
	client := server.Client()

	os.Mkdir("html/AuthTest", 0777)

	file, err := os.Create("html/AuthTest/index.html")
	if err != nil {
		t.Error("Unable to create testing data")
	}
	file.WriteString("Hello KatWeb!")
	file.Close()

	file, err = os.Create("html/AuthTest/passwd")
	if err != nil {
		t.Error("Unable to create testing data")
	}
	file.WriteString("3d8d3a0e7221998c93dc16df692c786fb170bfa93713f7f686f65d022f3040d8f50c845551b9c4f23c7c7068017c388db0bae3775307cf80d45451619f13c0b9\n2cbf59e5f532df22ea8d4f54566f35a3c885a12d2a8aa0c3ca3763b33740cc7a5605cd7b47f8495feeb1e6b019af7b6e6cefa697d43748718610031b551add5a\n")
	file.Close()

	defer os.RemoveAll("html/AuthTest")

	resp, err := testHostAuth(client, "KatWeb", "KatAuth", server.URL+"/AuthTest/")
	if err != nil {
		t.Error("Unable to connect to server!")
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	resp.Body.Close()
	if string(body) != "Hello KatWeb!" {
		t.Error("Basic authentication does not work correctly!")
	}

	resp, err = testHostAuth(client, "KatWeb", "KatWeb", server.URL+"/AuthTest/")
	if err != nil {
		t.Error("Unable to connect to server!")
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Unable to read request body!")
	}
	resp.Body.Close()
	if string(body) != "Hello KatWeb!" {
		t.Error("Basic authentication does not work correctly!")
	}

	if testHost(client, "localhost", server.URL+"/AuthTest/passwd") != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	if testHost(client, "localhost", server.URL+"/AuthTest/") != http.StatusUnauthorized {
		t.Error("Basic authentication does not work correctly!")
	}

	os.Remove("html/AuthTest/passwd")
	os.Create("html/AuthTest/passwd")

	if testHost(client, "localhost", server.URL+"/AuthTest/") != http.StatusForbidden {
		t.Error("Sandbox is not secure!")
	}

	server.Close()
}
