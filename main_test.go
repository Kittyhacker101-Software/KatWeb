/* KatWeb by kittyhacker101
This file contains unit tests for KatWeb.
Note that this will only test internal functions used within KatWeb at the moment. Manual testing is still highly recommended.
Current functions tested : detectPath, detectPasswd
Todo function tests : runAuth, loadHeaders (possibly), makeGzipHandler (possibly), wrapLoad (if required)*/
package main

import (
	"testing"
	"os"
)

func TestPathCache(t *testing.T) {
	conf.Cache.Run = true
	conf.Cache.Loc = "cache"
	path, url := detectPath("example.com/", "/"+conf.Cache.Loc+"/example.html")
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
	path, url := detectPath(conf.Cache.Loc+"/", "/example.html")
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
	path, url := detectPath("example.com/", "/"+conf.Proxy.Loc+"/example.html")
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
	path, url := detectPath(conf.Proxy.Loc+"/", "/example.html")
	if path != conf.Proxy.Loc {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, conf.Proxy.Loc)
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathSSL(t *testing.T) {
	path, url := detectPath("ssl/", "/example.html")
	if path != "html/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "html/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPathHTML(t *testing.T) {
	path, url := detectPath("html/", "/example.html")
	if path != "html/" {
		t.Errorf("Path was incorrect, got: %s, want: %s.", path, "html/")
	}
	if url != "/example.html" {
		t.Errorf("URL was incorrect, got: %s, want: %s.", url, "/example.html")
	}
}

func TestPasswd(t *testing.T) {
	finfo, err := os.Stat("html/DemoPass/passwd")
	if err != nil  {
		t.Fatalf("Unable to run test, testing file unreadable!")
	}

	auth := detectPasswd(finfo, "/DemoPass/passwd", "html/")
	if len(auth) != 2 || auth[0] != "admin" || auth[1] != "passwd" {
		t.Errorf("Auth was incorrect, got: %s, want: %s.", auth, []string{"admin", "passwd"})
	}
}
