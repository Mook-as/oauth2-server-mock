package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// TOKEN_SIGNING_KEY should be from `kato config get router2g aok/token_verification_key`
const TOKEN_SIGNING_KEY = "K0T5M4cgpSHIwCspHAJVSgyNP5cRljTzkk4rNpgnRRzbBOPLTgNJZmmKlcQC7sUt"

func writeError(w http.ResponseWriter, status int, msg string, args ...interface{}) {
	log.Printf("[ERROR] %s\n", fmt.Sprintf(msg, args...))
	w.WriteHeader(status)
	w.Header().Add("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, msg, args...)
}

// handleAuthEndpoint responds to /authorize with a form to submit
func handleAuthEndpoint(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Error parsing form: %s", err)
		return
	}
	tmpl, err := template.New("auth").Parse(`
		<html>
			<h1>OAuth2 authorization endpoint</h1>
			<table>
				<tr><th>key</th><th>value</th></tr>
				{{range $k, $v := .}}
					<tr><td>{{$k}}</td><td>{{$v}}</td></tr>
				{{end}}
			</table>
			<form method="post" action="/submit">
				<label>redirect_uri
					<input type="text" size="100" name="redirect_uri" value="{{index .redirect_uri 0}}">
				</label>
				<br>
				<label>state
					<input type="text" size="100" name="state" value="{{index .state 0}}">
				</label>
				<br>
				<input type="submit">
				<table>
			</form>
		</html>
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erroring filling auth template", err)
		return
	}
	w.Header().Add("Content-Type", "text/html")
	err = tmpl.Execute(w, req.Form)
}

// handleSubmitEndpoint responds to /submit with a redirect to the destination
func handleSubmitEndpoint(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Error parsing form: %s", err)
		return
	}
	target, err := url.Parse(string(req.Form.Get("redirect_uri")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Error parsing redirect uri: %s", err)
		return
	}
	query := target.Query()
	query.Add("state", string(req.Form.Get("state")))
	query.Add("code", "hello code")
	target.RawQuery = query.Encode()
	w.Header().Add("Location", target.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

// handleTokenEndpoint hands an oauth2 access token to the router
func handleTokenEndpoint(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Error parsing token data: %s", err)
		return
	}
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims = map[string]interface{}{
		"exp":       time.Now().Add(3600 * time.Second).UTC().Unix(),
		"user_id":   "fake_user",
		"user_name": "Fake User",
		"email":     "fake@user.invalid",
		"pants":     "Authenticated Pants",
	}
	signed_token, err := token.SignedString([]byte(TOKEN_SIGNING_KEY))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to sign token: %s", err)
		return
	}
	body, err := json.Marshal(map[string]interface{}{
		"expires_in":   3600,
		"access_token": signed_token,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode response: %s", err)
		return
	}
	log.Printf("JWT response: %s\n", body)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// handleFallback is the fallback handler to log issues
func handleFallback(w http.ResponseWriter, req *http.Request) {
	log.Printf("Got request to %s\n", req.URL.Path)
	writeError(w, http.StatusNotFound, "Path %s not found", req.URL.Path)
}

func main() {
	http.HandleFunc("/authorize", handleAuthEndpoint)
	http.HandleFunc("/submit", handleSubmitEndpoint)
	http.HandleFunc("/token", handleTokenEndpoint)
	http.HandleFunc("/", handleFallback)
	addr := ":" + os.Getenv("PORT")
	fmt.Printf("Listening on %v\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
