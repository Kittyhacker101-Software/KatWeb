/* KatWeb by kittyhacker101.
This file contains KatWeb APIs, parts of KatWeb which normally stay the same, and are easy to interface with.
Changes to an API's functionality, or additions/deletions of APIs will appear in the changelog.
Once enough KatWeb APIs are available, then you may be able to use these to make KatWeb however you wish. */
package main

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

/* DetectPasswd checks if a folder is set to be protected, and retrive the authentication credentials if required.
Inputs are (finfo, url, path).
Output will be provided in a string array, with [username, password] format.
If an error occures, ["err"] will be the output. */
func DetectPasswd(finfo os.FileInfo, url string, path string) []string {
	var tmp string

	if finfo.IsDir() {
		tmp = url
	} else {
		tmp = strings.TrimSuffix(url, finfo.Name())
	}

	b, err := ioutil.ReadFile(path + tmp + "passwd")
	if err == nil {
		tmpa := strings.Split(strings.TrimSpace(string(b)), ":")
		if len(tmpa) == 2 {
			return tmpa
		}
	}

	return []string{"err"}
}

/* DetectPath allows dynamic content control by domain.
Inputs are (r.Host+"/", r.URL.EscapedPath()). Outputs are path and url.
Note that this is not a fully external API currently, it still has some dependencies on KatWeb code. */
func DetectPath(path string, url string) (string, string) {
	if conf.Cache.Run && strings.HasPrefix(url, "/"+conf.Cache.Loc) {
		return conf.Cache.Loc + "/", strings.TrimPrefix(url, "/"+conf.Cache.Loc)
	}

	if conf.Proxy.Run {
		if strings.HasPrefix(url, "/"+conf.Proxy.Loc) || strings.TrimSuffix(path, "/") == conf.Proxy.Loc {
			return conf.Proxy.Loc, url
		}
	}

	_, err := os.Stat(path)
	if err == nil && path != "ssl/" {
		return path, url
	}

	return "html/", url
}

/* MakeGzipHandler adds a gzip wrapper to a http.HandlerFunc.
Inputs are (http.HandlerFunc, conf.Zip.Lvl).
Output will be a http.HandlerFunc. */
func MakeGzipHandler(funct http.HandlerFunc, level int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			funct(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")

		gz, err := gzip.NewWriterLevel(w, level)
		if err != nil {
			gz = gzip.NewWriter(w)
		}
		defer gz.Close()

		gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		funct(gzr, r)
	}
}

/* RunAuth runs HTTP basic authentication on a http.Request.
Inputs are (http.ResponseWriter, *http.Request, []string{username, password}).
Output will be true if login is correct, false if login is incorrect. */
func RunAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	user, pass, _ := r.BasicAuth()
	if len(a) == 2 && user == a[0] && pass == a[1] {
		return true
	}

	return false
}
