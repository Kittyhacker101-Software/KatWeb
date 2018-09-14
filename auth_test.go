package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

var (
	expectedLogins = []string{"601f8f22b15321a3cd342c1d50c6ce8da153da970d3dbfe25b3dbfa9326c3b30ac32d8725d8513fc43a5e7a97f637c502a0a1f05c997ebf4de7729676dba56d2", "7e9fc10177a7fa46bdf47a0849902a87e3431a961c7c3472068c862e325af388376174f8bbe3204da40369d9ea6ead0803e8a7e6450ff4fc195f6f4658827bcc", "9a83c7ec28250be89cef48d7698d68f4cd6e368e29c13395dbde5456a75422b58e85a2cd34d0e0e8a774df71f56010ef50ed7d869de3cf0ccc65aa600e980818"}
)

func IsCorrectPassword(client *http.Client, username, password, url string) (bool, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == 200 {
		return true, nil
	}

	return false, nil
}

func Test_DetectPasswd(t *testing.T) {
	logins := DetectPasswd("/DemoPass/index.html", "html")

	if !reflect.DeepEqual(logins, expectedLogins) {
		t.Fatal("DetectPasswd is not functioning correctly!")
	}

	logins = DetectPasswd("/DemoPass/", "html")

	if !reflect.DeepEqual(logins, expectedLogins) {
		t.Fatal("DetectPasswd is not functioning correctly!")
	}

	if !reflect.DeepEqual(DetectPasswd("/nonexistent", "html"), []string{"err"}) {
		t.Fatal("DetectPasswd is not functioning correctly!")
	}

	os.Mkdir("html/TestingPass", 0777)
	file, err := os.Create("html/TestingPass/passwd")
	if err != nil {
		t.Error("Unable to create testing data!")
	}
	file.Close()

	if !reflect.DeepEqual(DetectPasswd("/TestingPass/", "html"), []string{"forbid"}) {
		t.Fatal("DetectPasswd is not functioning correctly!")
	}

	os.RemoveAll("html/TestingPass")
}

func Test_RunAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RunAuth(w, r, expectedLogins) {
			http.Error(w, "Login successful", 200)
			return
		}

		http.Error(w, "Incorrect login", 403)
	}))
	client := server.Client()
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	}

	if resp.StatusCode == 200 {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err := IsCorrectPassword(client, "admin", "incorrectpassword", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err = IsCorrectPassword(client, "incorrectusername", "password", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err = IsCorrectPassword(client, "incorrectusername", "incorrectpassword", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err = IsCorrectPassword(client, "admin", "password", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if !ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err = IsCorrectPassword(client, "admin", "admin", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}

	ok, err = IsCorrectPassword(client, "password", "password", server.URL)
	if err != nil {
		t.Fatal("Unable to get testing data!")
	} else if ok {
		t.Fatal("RunAuth is not functioning correctly!")
	}
}
