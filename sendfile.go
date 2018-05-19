// KatWeb by kittyhacker101 - HTTP(S) Content Writing
package main

import (
	"github.com/klauspost/compress/gzip"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// IndexFile is the file name for directory index files
const IndexFile = "index.html"

var (
	htmlReplacer = strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	)
	zippers = sync.Pool{New: func() interface{} {
		gz, _ := gzip.NewWriterLevel(nil, gzip.BestCompression)
		return gz
	}}
	gztypes = []string{"application/javascript", "application/json", "application/x-javascript", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml"}
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

	if finfo, err = file.Stat(); err != nil {
		return err
	}

	w.Header().Set("Content-Type", getMime(file, finfo))

	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		if _, err = os.Stat(location + ".br"); err == nil && strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
			if filen, err := os.Open(location + ".br"); err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "br")
			}
		} else if _, err = os.Stat(location + ".gz"); err == nil {
			if filen, err := os.Open(location + ".gz"); err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "gzip")
			}
		} else if finfo.Size() < 100000 && finfo.Size() < 400 && w.Header().Get("Content-Type") != "application/gzip" {
			ct := strings.Split(w.Header().Get("Content-Type"), ";")
			i := sort.SearchStrings(gztypes, ct[0])
			if i < len(gztypes) && gztypes[i] == ct[0] {
				if filen, err := os.Create(location + ".gz"); err == nil {
					gz := zippers.Get().(*gzip.Writer)
					gz.Reset(filen)

					io.Copy(gz, file)

					gz.Close()
					zippers.Put(gz)
					file.Close()

					file = filen
					w.Header().Set("Content-Encoding", "gzip")
				}
			}
		}
	}

	http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), file)
	return file.Close()
}

func getMime(f io.ReadSeeker, fi os.FileInfo) string {
	mime := mime.TypeByExtension(filepath.Ext(fi.Name()))
	if mime != "" {
		return mime
	}

	var buf [512]byte
	n, _ := io.ReadFull(f, buf[:])
	mime = http.DetectContentType(buf[:n])
	f.Seek(0, io.SeekStart)
	return mime
}

func dirList(w http.ResponseWriter, f os.File, urln string) error {
	dirs, err := f.Readdir(-1)
	if err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><style>body,html{margin:0;font:15px/1.5 sans-serif}h1,h3{font-weight:400;margin:10px 0}h1{font-size:48px;padding:16px 0}a,h3{text-align:center}h3{font-size:24px}a,header{color:#fff}a{width:98.5%;display:inline-block;text-decoration:none;cursor:pointer;background-color:#616161;padding:8px 16px}header{background-color:teal;padding:64px 16px 64px 32px}div{padding:.01em 16px}</style><title>` + urln + `</title><header><h1>` + urln + `</h1></header><div style="padding:16px;"><h3>Contents of directory</h3><div style="max-width:800px;margin:auto">`))
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

// StyledError serves an styled error page
func StyledError(w http.ResponseWriter, title string, content string, status int) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><style>body{margin:0;font:15px/1.5 sans-serif}h1,h3{font-weight:400;margin:10px 0}h1{font-size:48px;padding:16px 0}h3{font-size:24px}header{color:#fff;background-color:teal;padding:64px 16px 64px 32px}</style><title>` + title + `</title><header><h1>` + title + `</h1></header><div style="padding:16px;"><h3>` + content + `</h3></div></div>`))
}
