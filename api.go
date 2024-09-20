package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func handleRequests(w http.ResponseWriter, r *http.Request) {
	mutex.Lock()
	defer mutex.Unlock()

	requestList := make([]map[string]string, len(requests))
	for i, req := range requests {
		requestList[i] = map[string]string{
			"Method": req.Method,
			"URL":    req.URL.String(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requestList)
}

func handleRequestByID(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/requests/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id < 0 || id >= len(requests) {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	req := requests[id]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"Method": req.Method,
		"URL":    req.URL.String(),
	})
}
