// KatWeb by kittyhacker101 - HTTP Basic Authentication
package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
)

// RunAuth runs basic authentication on a http.Request
// The input []string must be a list of sha512 hashes.
// If the user provided a correct login, this function will return true.
func RunAuth(w http.ResponseWriter, r *http.Request, a []string) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Please enter your login credentials."`)
	user, pass, _ := r.BasicAuth()
	hn := sha512.Sum512([]byte(user + ":" + pass))
	hash := hex.EncodeToString(hn[:])

	for _, e := range a {
		if e == hash {
			return true
		}
	}

	return false
}

// DetectPasswd gets password protection settings, and authentication credentials.
// If the file does not exist, the value ["err"] will be returned.
// If the file is blank, ["forbid"] will be returned.
func DetectPasswd(url string, path string) []string {
	tmp, _ := filepath.Split(url)

	if f, err := os.Open(path + tmp + "passwd"); err == nil {
		var data []string
		s := bufio.NewScanner(f)
		for s.Scan() {
			data = append(data, s.Text())
		}
		if len(data) == 0 {
			return []string{"forbid"}
		}

		return data
	}

	return []string{"err"}
}
