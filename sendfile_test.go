// KatWeb by kittyhacker101 - Sendfile Unit Tests
package main

import (
	"net/http"
	"net/http/httptest"
	"bytes"
	"strings"
	"os"
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
			http.Error(w, "Unable to read directory" ,500)
			return
		}
		if dirList(w, *file, "localTest/html") != nil {
			http.Error(w, "Unable to crawl directory" ,500)
		}
	}))
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("DirList is not functioning correctly!")
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "localTest/html") || !strings.Contains(buf.String(), "index.html") || !strings.Contains(buf.String(), "DemoPass") || !strings.Contains(buf.String(), "special ^&#34;&#39;.test") {
		Print(buf.String())
		t.Fatal("DirList is not functioning correctly!")
	}

	resp.Body.Close()
}
