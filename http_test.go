// KatWeb by kittyhacker101 - HTTP Unit Tests
package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func Test_httpsredir(t *testing.T) {
	conf.Adv.HTTPS = 443

	server := httptest.NewServer(httpsredir)
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	parsedURL := strings.Split(server.URL, ":")
	conf.Adv.HTTP, err = strconv.Atoi(parsedURL[2])
	if err != nil {
		t.Error("Unable to edit server configuration!")
	}

	if resp.Header.Get("Location") != "https://127.0.0.1:"+parsedURL[2]+"/" {
		t.Error("httpsredir is not functioning properly!")
	}

	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.Header.Get("Location") != "https://127.0.0.1/" {
		t.Error("httpsredir is not functioning properly!")
	}

	conf.Adv.HTTPS = 8181

	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.Header.Get("Location") != "https://127.0.0.1:8181/" {
		t.Error("httpsredir is not functioning properly!")
	}
}

func Test_getFormattedURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(getFormattedURL(r)))
	}))

	resp, err := server.Client().Get(server.URL + `/special ^"'.test`)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != `/special ^"'.test` {
		t.Fatal("getFormattedURL is not functioning correctly!")
	}
}

func Test_trimPort(t *testing.T) {
	if trimPort("") != "html" {
		t.Fatal("trimPort is not functioning correctly!")
	}

	if trimPort("127.0.0.1") != "127.0.0.1" {
		t.Fatal("trimPort is not functioning correctly!")
	}

	if trimPort("[100::ffff:ffff:ffff:ffff]") != "[100::ffff:ffff:ffff:ffff]" {
		t.Fatal("trimPort is not functioning correctly!")
	}

	if trimPort("127.0.0.1:8080") != "127.0.0.1" {
		t.Fatal("trimPort is not functioning correctly!")
	}

	if trimPort("[100::ffff:ffff:ffff:ffff]:8080") != "[100::ffff:ffff:ffff:ffff]" {
		t.Fatal("trimPort is not functioning correctly!")
	}
}

func Test_mainHandle(t *testing.T) {
	ParseConfig("conf.json")
	server := httptest.NewServer(http.HandlerFunc(mainHandle))

	resp, err := server.Client().Get(server.URL + `//../`)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 403 {
		t.Fatal("mainHandle is not sandboxed properly!")
	}

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Host = "ssl"

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 403 {
		t.Fatal("mainHandle is not sandboxed properly!")
	}

	req, err = http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Host = ".."

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 403 {
		t.Fatal("mainHandle is not sandboxed properly!")
	}

	req, err = http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Host = "."

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 403 {
		t.Fatal("mainHandle is not sandboxed properly!")
	}
}
