// KatWeb by kittyhacker101 - Unit Tests
// NOTE: These tests will not work properly if you have edited the contents of the "html" folder in any way!
package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"os"
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

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Error("Unable to create request!")
	}
	req.Host = "testinghost"

	resp, err := client.Do(req)
	if err != nil {
		t.Error("Unable to connect to server!")
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
