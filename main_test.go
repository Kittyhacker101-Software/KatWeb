/* KatWeb by kittyhacker101
This file contains unit tests for some KatWeb APIs.
Currently tested APIs : DetectPath, DetectPasswd, MakeGzipHandler, RunAuth
Untested APIs :  */
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPathCache(t *testing.T) {
	path, url := DetectPath("example.com/", "/cache/example.html", "cache", "norun")
	if path != "cache/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "cache/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathCacheHost(t *testing.T) {
	path, url := DetectPath("cache/", "/example.html", "cache", "norun")
	if path != "cache/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "cache/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathProxy(t *testing.T) {
	path, url := DetectPath("example.com/", "/proxy/example.html", "norun", "proxy")
	if path != "proxy" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "proxy")
	}
	if url != "/proxy/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/proxy/example.html")
	}
}

func TestPathProxyHost(t *testing.T) {
	path, url := DetectPath("proxy/", "/example.html", "norun", "proxy")
	if path != "proxy" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "proxy")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathSSL(t *testing.T) {
	path, url := DetectPath("ssl/", "/example.html", "norun", "norun")
	if path != "html/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "html/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathHTML(t *testing.T) {
	path, url := DetectPath("html/", "/example.html", "norun", "norun")
	if path != "html/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "html/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPasswd(t *testing.T) {
	finfo, err := os.Stat("html/DemoPass/passwd")
	if err != nil {
		t.Fatalf("Unable to run test, testing file unreadable!")
	}

	auth := DetectPasswd(finfo, "/DemoPass/passwd", "html/")
	if len(auth) != 2 || auth[0] != "admin" || auth[1] != "passwd" {
		t.Errorf("Auth was incorrect, got: %s, want: %s.", auth, []string{"admin", "passwd"})
	}
}

func TestGzipHandler(t *testing.T) {
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello world!")
	}
	gzipHandle := MakeGzipHandler(mainHandle, 6)

	req, err := http.NewRequest("GET", "/example.html", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(gzipHandle)
	handler.ServeHTTP(rr, req)

	ctype := rr.Header().Get("Content-Encoding")
	if ctype != "gzip" {
		t.Errorf("Content-Encoding header does not match: got %v want %v", ctype, "gzip")
	}
}

func TestAuthBlock(t *testing.T) {
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		if RunAuth(w, r, []string{"admin", "passwd"}) {
			io.WriteString(w, "Hello world!")
		} else {
			http.Error(w, "401 Unauthorized : Authentication is required and has failed or has not yet been provided.", http.StatusUnauthorized)
		}
	}
	req, err := http.NewRequest("GET", "/example.html", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(mainHandle)
	handler.ServeHTTP(rr, req)

	status := rr.Code
	if status != http.StatusUnauthorized {
		t.Errorf("HTTP status does not match: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestAuthAllow(t *testing.T) {
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		if RunAuth(w, r, []string{"admin", "passwd"}) {
			io.WriteString(w, "Hello world!")
		} else {
			http.Error(w, "401 Unauthorized : Authentication is required and has failed or has not yet been provided.", http.StatusUnauthorized)
		}
	}
	req, err := http.NewRequest("GET", "/example.html", nil)
	req.SetBasicAuth("admin", "passwd")
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(mainHandle)
	handler.ServeHTTP(rr, req)

	status := rr.Code
	if status != http.StatusOK {
		t.Errorf("HTTP status does not match: got %v want %v", status, http.StatusOK)
	}
}
