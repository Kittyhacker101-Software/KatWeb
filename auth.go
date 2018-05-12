// KatWeb by kittyhacker101 - HTTP Basic Authentication
package main

import (
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
)

// RunAuth runs basic authentication on a http.Request
func RunAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	if user, pass, _ := r.BasicAuth(); len(a) == 2 && user == a[0] && pass == a[1] {
		return true
	}

	return false
}

// DetectPasswd gets password protection settings, and authentication credentials.
func DetectPasswd(url string, path string) ([]string, bool) {
	tmp, _ := filepath.Split(url)

	if b, err := ioutil.ReadFile(path + tmp + "passwd"); err == nil {
		if tmpa := strings.Split(strings.TrimSpace(string(b)), ":"); len(tmpa) == 2 {
			return tmpa, true
		}
	}

	return []string{"err"}, false
}
