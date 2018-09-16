// KatWeb by kittyhacker101 - Sendfile Unit Tests
package main

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func statOpen(path string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	finfo, err := file.Stat()
	if err != nil {
		return file, nil, err
	}

	return file, finfo, nil
}

func testReadGzipFile(t *testing.T) []byte {
	fi, err := os.Open("html/index.html.gz")
	if err != nil {
		t.Fatal("Unable to read gzipped file!")
	}
	defer fi.Close()

	fz, err := gzip.NewReader(fi)
	if err != nil {
		t.Fatal("Unable to read gzipped file!")
	}
	defer fz.Close()

	s, err := ioutil.ReadAll(fz)
	if err != nil {
		t.Fatal("Unable to read gzipped file!")
	}
	return s
}

func Test_isZipped(t *testing.T) {
	file, finfo, err := statOpen("html/index.html")
	if err != nil {
		t.Fatal("Unable to read index file!")
	}

	if !isZipped(finfo, file, "html/index.html") {
		t.Fatal("isZipped is not functioning correctly!")
	}

	os.Remove("html/index.html.gz")

	if !isZipped(finfo, file, "html/index.html") {
		t.Fatal("isZipped is not functioning correctly!")
	}

	data, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	if !bytes.Equal(data, testReadGzipFile(t)) {
		t.Fatal("isZipped is not functioning correctly!")
	}

	file, err = os.Create("html/test.txt")
	if err != nil {
		t.Error("Unable to create testing data!")
	}
	file.WriteString("Hello KatWeb!")
	file.Close()

	file, finfo, err = statOpen("html/test.txt")
	if err != nil {
		t.Fatal("Unable to read index file!")
	}

	if isZipped(finfo, file, "html/test.txt") {
		t.Fatal("isZipped is not functioning correctly!")
	}

	os.Remove("html/test.txt")
}

func Test_getMime(t *testing.T) {
	file, finfo, err := statOpen("html/index.html")
	if err != nil {
		t.Fatal("Unable to read index file!")
	}

	if getMime(file, finfo) != "text/html; charset=utf-8" {
		t.Fatal("getMime is not functioning correctly!")
	}

	file, finfo, err = statOpen("html/index.html.gz")
	if err != nil {
		t.Fatal("Unable to read index file!")
	}

	if getMime(file, finfo) != "application/gzip" {
		t.Fatal("getMime is not functioning correctly!")
	}

	file, err = os.Create("html/testFile")
	if err != nil {
		t.Error("Unable to create testing data!")
	}
	file.WriteString("Hello KatWeb!")

	finfo, err = file.Stat()
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	if getMime(file, finfo) != "text/plain; charset=utf-8" {
		t.Fatal("getMime is not functioning correctly!")
	}

	os.Remove("html/testFile")
}

func Test_StyledError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StyledError(w, "Hi", "Hello KatWeb!", 200)
	}))
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("StyledError is not functioning correctly!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "Hi") || !strings.Contains(buf.String(), "Hello KatWeb!") {
		t.Fatal("StyledError is not functioning correctly!")
	}

	resp.Body.Close()
}

func Test_dirList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, err := os.Open("html")
		if err != nil {
			http.Error(w, "Unable to read directory", 500)
			return
		}
		if dirList(w, *file, "localTest/html") != nil {
			t.Fatal("dirList is not functioning correctly!")
		}
	}))
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("dirList is not functioning correctly!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "localTest/html") || !strings.Contains(buf.String(), "index.html") || strings.Contains(buf.String(), "index.html.br") || !strings.Contains(buf.String(), "DemoPass") || !strings.Contains(buf.String(), "special ^&#34;&#39;.test") {
		t.Fatal("dirList is not functioning correctly!")
	}

	resp.Body.Close()
}

func Test_ServeFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlo, err := url.QueryUnescape(r.URL.EscapedPath())
		if err != nil {
			http.Error(w, "Bad request.", 400)
		}
		if ServeFile(w, r, "html/"+urlo, urlo) != nil {
			http.Error(w, "An error has occurred.", 500)
		}
	}))
	resp, err := server.Client().Get(server.URL + "/nonexistentfile")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 500 {
		t.Fatal("ServeFile is not functioning correctly!")
	}

	resp, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	data, err := ioutil.ReadFile("html/index.html")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || string(data) != buf.String() {
		t.Fatal("ServeFile is not functioning correctly!")
	}

	resp, err = server.Client().Get(server.URL + `/special ^"'.test`)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	data, err = ioutil.ReadFile(`html/special ^"'.test`)
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || string(data) != buf.String() {
		Print(buf.String())
		t.Fatal("ServeFile is not functioning correctly!")
	}

	resp, err = server.Client().Get(server.URL + "/DemoPass/")
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(buf.String(), "/DemoPass/") || !strings.Contains(buf.String(), "passwd") {
		t.Fatal("ServeFile is not functioning correctly!")
	}

}

func Test_ServeFile_Compression(t *testing.T) {
	conf.Adv.Dev = false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ServeFile(w, r, "html/"+r.URL.String(), r.URL.String()) != nil {
			http.Error(w, "An error has occurred.", 500)
		}
	}))
	server.Client().Transport.(*http.Transport).DisableCompression = true

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Header.Add("Accept-Encoding", "br")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	data, err := ioutil.ReadFile("html/index.html.br")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || string(data) != buf.String() {
		t.Fatal("ServeFile is not functioning correctly!")
	}

	req, err = http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}
	req.Header.Add("Accept-Encoding", "gzip")

	resp, err = server.Client().Do(req)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	data, err = ioutil.ReadFile("html/index.html.gz")
	if err != nil {
		t.Error("Unable to read testing data!")
	}

	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 || string(data) != buf.String() {
		t.Fatal("ServeFile is not functioning correctly!")
	}
}
