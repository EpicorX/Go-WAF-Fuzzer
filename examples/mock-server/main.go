package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		payload := extractPayload(r)
		if looksSuspicious(payload) {
			http.Error(w, "blocked by demo rule", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision": "allow",
			"payload":  payload,
		})
	})

	log.Println("demo mock WAF listening on http://127.0.0.1:8080/inspect")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}

func extractPayload(r *http.Request) string {
	if value := r.URL.Query().Get("input"); value != "" {
		return value
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		if err := r.ParseForm(); err == nil {
			return r.Form.Get("input")
		}
	case strings.Contains(contentType, "application/json"):
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			return body["input"]
		}
	}

	return ""
}

func looksSuspicious(payload string) bool {
	lowered := strings.ToLower(payload)
	keywords := []string{
		"sqli-probe-string",
		"xss-probe-string",
		"traversal-probe-string",
		"deser-probe-string",
	}

	for _, keyword := range keywords {
		if strings.Contains(lowered, keyword) {
			return true
		}
	}

	return false
}
