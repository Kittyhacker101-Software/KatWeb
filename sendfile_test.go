// KatWeb by kittyhacker101 - Sendfile Unit Tests
package main

import (
	//"net/http"
	//"net/http/httptest"
	//"runtime/debug"
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
