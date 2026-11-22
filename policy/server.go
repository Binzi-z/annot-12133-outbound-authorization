package policy

import (
	"encoding/json"
	"net/http"
)

// ServeHTTP exposes the service over loopback HTTP:
//
//	GET  /bundle            -> current bundle
//	GET  /watch?v=N         -> blocks until version > N, then returns bundle
//	POST /publish           -> publish snapshot
//	POST /rollback?gen=N    -> roll back to generation N
//	GET  /history           -> all snapshots
func (svc *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/bundle":
		writeJSON(w, svc.Bundle())
	case "/watch":
		svc.serveWatch(w, r)
	case "/publish":
		var snap Snapshot
		if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := svc.Publish(snap); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, svc.Bundle())
	case "/rollback":
		var req struct {
			Generation int64 `json:"generation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		snap, err := svc.Rollback(req.Generation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, snap)
	case "/history":
		writeJSON(w, svc.History())
	default:
		http.NotFound(w, r)
	}
}

func (svc *Service) serveWatch(w http.ResponseWriter, r *http.Request) {
	v := int64(0)
	if raw := r.URL.Query().Get("v"); raw != "" {
		if _, err := parseInt64(raw, &v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	ch := svc.Notify()
	if svc.Version() <= v {
		select {
		case <-ch:
		case <-r.Context().Done():
			http.Error(w, "watch closed", http.StatusRequestTimeout)
			return
		}
	}
	writeJSON(w, svc.Bundle())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
