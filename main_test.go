/* KatWeb by kittyhacker101
This file contains unit tests for KatWeb APIs.
Currently tested APIs : DetectPath, DetectPasswd
Untested APIs : MakeGzipHandler, RunAuth */
package main

import (
	//"net/http"
	//"net/http/httptest"
	"os"
	"testing"
)

func TestPathCache(t *testing.T) {
	conf.Cache.Run = true
	conf.Cache.Loc = "cache"
	path, url := DetectPath("example.com/", "/"+conf.Cache.Loc+"/example.html")
	if path != conf.Cache.Loc+"/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, conf.Cache.Loc+"/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathCacheHost(t *testing.T) {
	conf.Cache.Run = true
	conf.Cache.Loc = "cache"
	path, url := DetectPath(conf.Cache.Loc+"/", "/example.html")
	if path != conf.Cache.Loc+"/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, conf.Cache.Loc+"/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathProxy(t *testing.T) {
	conf.Proxy.Run = true
	conf.Proxy.Loc = "proxy"
	path, url := DetectPath("example.com/", "/"+conf.Proxy.Loc+"/example.html")
	if path != conf.Proxy.Loc {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, conf.Proxy.Loc)
	}
	if url != "/"+conf.Proxy.Loc+"/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/"+conf.Proxy.Loc+"/example.html")
	}
}

func TestPathProxyHost(t *testing.T) {
	conf.Proxy.Run = true
	conf.Proxy.Loc = "proxy"
	path, url := DetectPath(conf.Proxy.Loc+"/", "/example.html")
	if path != conf.Proxy.Loc {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, conf.Proxy.Loc)
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathSSL(t *testing.T) {
	path, url := DetectPath("ssl/", "/example.html")
	if path != "html/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "html/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathHTML(t *testing.T) {
	path, url := DetectPath("html/", "/example.html")
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

/* func TestGzipHandler(t *testing.T) {
	mainHandle := func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Hello world!")
	}
} */
