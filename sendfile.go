// KatWeb by kittyhacker101 - HTTP(S) Content Writing
package main

import (
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// IndexFile is the file name for directory index files
const IndexFile = "index.html"

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&#34;",
	"'", "&#39;",
)

// ServeFile writes the contents of a file or directory into the HTTP response
func ServeFile(w http.ResponseWriter, r *http.Request, loc string, folder string) error {
	var location = loc

	finfo, err := os.Stat(loc)
	if err != nil {
		return err
	}

	if finfo.IsDir() {
		location = loc + IndexFile
	}

	file, err := os.Open(location)
	if err != nil {
		if strings.HasSuffix(location, IndexFile) {
			// If the index file is not present, create a list of files in the directory
			if file, err := os.Open(loc); err == nil {
				return dirList(w, *file, folder)
			}
		}
		return err
	}

	finfo, err = file.Stat()
	if err != nil {
		return err
	}

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && conf.Pef.GZ == 0 {
		if _, err = os.Stat(location + ".br"); err == nil && strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
			filen, err := os.Open(location + ".br")
			if err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "br")
			}
		} else if _, err = os.Stat(location + ".gz"); err == nil {
			filen, err := os.Open(location + ".gz")
			if err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "gzip")
			}
		}
	}

	http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), file)
	return file.Close()
}

func dirList(w http.ResponseWriter, f os.File, urln string) error {
	dirs, err := f.Readdir(-1)
	if err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><html lang=en><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><style>body,html{font-family:Verdana,sans-serif;font-size:15px;line-height:1.5;margin:0}h1,h3{font-family:Segoe UI,Arial,sans-serif;font-weight:400;margin:10px 0}h1{font-size:48px;padding:16px 0}a,h3{text-align:center}h3{font-size:24px}a,header{color:#fff}a{width:98.5%;display:inline-block;text-decoration:none;cursor:pointer;background-color:#616161;padding:8px 16px}header{background-color:#009688;padding:64px 16px 64px 32px}div{padding:.01em 16px}</style><header><h1>` + urln + `</h1></header><div style="padding:16px;"><h3>Contents of directory</h3><div style="max-width:800px;margin:auto">`))
	for _, d := range dirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		// Escape special characters from the url path
		url := url.URL{Path: name}
		w.Write([]byte("<p></p><a href=" + htmlReplacer.Replace(name) + ">" + url.String() + "</a>"))
	}
	w.Write([]byte("</div></div></div>"))
	return nil
}
