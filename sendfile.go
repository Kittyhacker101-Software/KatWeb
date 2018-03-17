// KatWeb by kittyhacker101 - HTTP(S) Content Writing
package main

import (
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

const indexFile string = "index.html"
const serverError string = "500 Internal Server Error : An unexpected condition was encountered."

func ServeFile(w http.ResponseWriter, r *http.Request, loc string, folder string) error {
	var location string = loc

	finfo, err := os.Stat(loc)
	if err != nil {
		return err
	}

	if finfo.IsDir() {
		location = loc + indexFile
	}

	file, err := os.Open(location)
	if err != nil {
		if strings.HasSuffix(location, indexFile) {
			// If the index file is not present, create a list of files in the directory
			file, err := os.Open(loc)
			if err == nil {
				err = dirList(w, *file, folder)
				if err != nil {
					return err
				}
				return nil
			}
		}
		http.Error(w, serverError, http.StatusInternalServerError)
		return err
	}

	finfo, err = file.Stat()
	if err != nil {
		http.Error(w, serverError, http.StatusInternalServerError)
		return err
	}
	http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), file)
	file.Close()
	return nil
}

func dirList(w http.ResponseWriter, f os.File, urln string) error {
	dirs, err := f.Readdir(-1)
	if err != nil {
		http.Error(w, "Error reading directory.", http.StatusInternalServerError)
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
