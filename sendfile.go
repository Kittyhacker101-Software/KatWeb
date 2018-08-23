// KatWeb by kittyhacker101 - HTTP(S) Content Writing
package main

import (
	"github.com/klauspost/compress/gzip"
	"html/template"
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
	zippers = sync.Pool{New: func() interface{} {
		gz, err := gzip.NewWriterLevel(nil, gzip.BestCompression)
		if err != nil {
			gz = gzip.NewWriter(nil)
		}
		return gz
	}}
	gztypes = []string{"application/javascript", "application/json", "application/x-javascript", "image/svg+xml", "text/css", "text/csv", "text/html", "text/plain", "text/xml"}
)

// ServeFile writes the contents of a file or directory into the HTTP response
func ServeFile(w http.ResponseWriter, r *http.Request, loc string, folder string) error {
	var (
		location = loc
		filen    *os.File
	)

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
			// If the index file is not present, send a list of files in the directory
			if file, err = os.Open(loc); err == nil {
				return dirList(w, *file, folder)
			}
		}
		return err
	}

	if finfo, err = file.Stat(); err != nil {
		return err
	}

	w.Header().Set("Content-Type", getMime(file, finfo))

	if !conf.Adv.Dev && r.Header.Get("Accept-Encoding") != "" {
		if _, err = os.Stat(location + ".br"); err == nil && strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
			if filen, err = os.Open(location + ".br"); err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "br")
			}
		} else if isZipped(w, finfo, file, location) && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			if filen, err = os.Open(location + ".gz"); err == nil {
				file.Close()
				file = filen
				w.Header().Set("Content-Encoding", "gzip")
			}
		}
	}

	http.ServeContent(w, r, finfo.Name(), finfo.ModTime(), file)
	return file.Close()
}

// getMime detects the correct value for the "Content-Type" header.
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
	dirs, err := f.Readdirnames(0)
	if err != nil {
		return err
	}
	sort.Strings(dirs)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><title>` + urln + `</title><style>body{margin:0;font:16px/1.5 sans-serif}h1,h3{font-weight:400;margin:10px 0}h1{font-size:48px}h3{font-size:24px;padding-top:16px}a,header{color:#fff}a{width:98.5%;display:inline-block;text-decoration:none;background-color:#333e42;padding:8px 16px}a,h3{text-align:center}header{background-color:#222d32;padding:80px 32px}div{max-width:800px;margin:auto;padding:.01em 64px}</style><header><h1>` + urln + `</h1></header><h3>Contents of directory</h3><div>`))
	for _, d := range dirs {
		// Escape special characters from the url path
		if strings.HasSuffix(d, ".br") || (strings.HasSuffix(d, ".gz") && !strings.HasSuffix(d, ".tar.gz")) {
			continue
		}
		url := url.URL{Path: d}
		w.Write([]byte("<p><a href=" + template.HTMLEscapeString(url.String()) + ">" + template.HTMLEscapeString(d) + "</a>"))
	}
	w.Write([]byte("</div>"))
	return nil
}

// StyledError serves an styled error page
func StyledError(w http.ResponseWriter, title string, content string, status int) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!DOCTYPE html><title>` + title + `</title><meta content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1" name=viewport><style>body{margin:0;font:16px/1.5 sans-serif}h1,h3{font-weight:400;margin:10px 0}h1{font-size:48px}h3{font-size:24px;padding:16px}header{color:#fff;background-color:#222d32;padding:80px 32px}</style><header><h1>` + title + `</h1></header><h3>` + content + `</h3>`))
}

// isZipped returns true if a gzipped version of the file exists.
// If a gzipped version of the file does not exist, it will attempt
// to compress the file in real time, and return true if the
// attempt is sucessful.
func isZipped(w http.ResponseWriter, finfo os.FileInfo, file io.ReadCloser, filePath string) bool {
	if _, err := os.Stat(filePath + ".gz"); err == nil {
		return true
	}

	if finfo.Size() < 100000 && finfo.Size() > 400 && w.Header().Get("Content-Type") != "application/gzip" {
		ct := strings.Split(w.Header().Get("Content-Type"), ";")
		i := sort.SearchStrings(gztypes, ct[0])
		if i < len(gztypes) && gztypes[i] == ct[0] {
			if filen, err := os.Create(filePath + ".gz"); err == nil {
				gz := zippers.Get().(*gzip.Writer)
				gz.Reset(filen)

				io.Copy(gz, file)

				gz.Close()
				zippers.Put(gz)
				file.Close()

				return true
			}
		}
	}

	return false
}
