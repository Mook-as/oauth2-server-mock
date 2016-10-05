package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
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
				<tr><th>key<th>value
				{{range $k, $v := .form}}
					<tr><td>{{$k}}<td>{{$v}}
				{{end}}
			</table>
			<form method="post" action="/submit">
				<table>
					<tr>
						<th>redirect_uri
						<td><input type="text" size="100" name="redirect_uri" value="{{index .form.redirect_uri 0}}">
					<tr>
						<th>state
						<td><input type="text" size="100" name="state" value="{{index .form.state 0}}">
					<tr>
						<th>claims
						<td><textarea name="claims" rows="20" cols="80">{{range .claims}}{{printf "%s\n" .}}{{end}}</textarea>
					<tr>
						<input type="submit">
					</tr>
				<table>
			</form>
		</html>
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Erroring filling auth template", err)
		return
	}
	data := map[string]interface{}{
		"claims": []string{
			"user_id=fake_user",
			"user_name=Fake User",
			"email=fake@user.invalid",
			"extra=Extra Authenticated Value",
		},
		"form": req.Form,
	}
	w.Header().Add("Content-Type", "text/html")
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error filling template: %s\n", err.Error())
		writeError(w, http.StatusInternalServerError, "Erroring filling auth template", err)
		return
	}
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
	query.Add("code", string(req.Form.Get("claims")))
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
	for _, line := range strings.Split(req.Form.Get("code"), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(fields) == 2 {
			token.Claims[fields[0]] = fields[1]
		}
	}
	token.Claims["exp"] = time.Now().Add(3600 * time.Second).UTC().Unix()
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
	w.Header().Set("Content-Type", "application/json")
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
