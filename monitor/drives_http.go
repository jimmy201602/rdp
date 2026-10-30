package monitor

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"rdp.local/kernel/gateway"
)

func (m *Monitor) driveRoutes(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /api/sessions/{id}/devices", func(w http.ResponseWriter, r *http.Request) {
		s := m.Session(r.PathValue("id"))
		if s == nil {
			http.Error(w, "session not found", 404)
			return
		}
		writeJSON(w, s.Devices())
	})
	handle := func(w http.ResponseWriter, r *http.Request) { m.serveDrive(w, r, token) }
	mux.HandleFunc("GET /api/sessions/{id}/drives/{device}/entries", handle)
	mux.HandleFunc("GET /api/sessions/{id}/drives/{device}/file", handle)
	mux.HandleFunc("PUT /api/sessions/{id}/drives/{device}/file", handle)
	mux.HandleFunc("DELETE /api/sessions/{id}/drives/{device}/file", handle)
}

func (m *Monitor) serveDrive(w http.ResponseWriter, r *http.Request, token string) {
	w.Header().Set("Cache-Control", "no-store")
	// Query-string tokens must never grant file access or mutations.
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	bearer := token != "" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && subtle.ConstantTimeCompare([]byte(auth), []byte(token)) == 1
	login := m.auth.userFor(r)
	if !m.cfg.AllowDriveControl || token == "" || !bearer && login == "" {
		http.Error(w, "drive control requires -monitor-drive-control and a bearer token or login", http.StatusForbidden)
		return
	}
	s := m.Session(r.PathValue("id"))
	if s == nil {
		http.Error(w, "session not found", 404)
		return
	}
	// A logged-in user reaches only the folder of a web session they opened;
	// other sessions' drives need the API token.
	if !bearer {
		s.mu.Lock()
		own := s.ctl.Web && s.owner == login
		s.mu.Unlock()
		if !own {
			http.Error(w, "only the session's own user or the API token may browse its drives", http.StatusForbidden)
			return
		}
	}
	id, err := strconv.ParseUint(r.PathValue("device"), 10, 32)
	if err != nil {
		http.Error(w, "invalid device", 400)
		return
	}
	path, err := drivePath(r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	listing := strings.HasSuffix(r.URL.Path, "/entries")
	if !listing && path == "\\" {
		http.Error(w, "the mapped root cannot be read, overwritten or deleted as a file", 400)
		return
	}
	if r.Method == http.MethodPut && (r.ContentLength < 0 || r.ContentLength > maxDriveFile) {
		http.Error(w, "upload needs a known length of at most 64 MiB", 413)
		return
	}
	select {
	case s.audit.operations <- struct{}{}:
		defer func() { <-s.audit.operations }()
	default:
		http.Error(w, "another drive operation is in progress", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	action := map[string]string{"GET": "admin_download", "PUT": "admin_upload", "DELETE": "admin_delete"}[r.Method]
	if listing {
		action = "browse"
	}
	event := Event{Kind: "file", Source: "admin", Action: action, Device: uint32(id), Path: path, Status: "started", Detail: r.RemoteAddr}
	s.emit(event)
	defer func() {
		event.Status = "ok"
		if err != nil {
			event.Status = "failed"
		}
		s.emit(event)
	}()
	if s.ctl.Web {
		if err = s.serveWebDrive(ctx, w, r, uint32(id), path, listing, &event); err != nil {
			code := http.StatusBadGateway
			if errors.Is(err, errNoWebFolder) || errors.Is(err, gateway.FSErrExists) || errors.Is(err, gateway.FSErrNotFound) {
				code = http.StatusConflict
			}
			http.Error(w, err.Error(), code)
		}
		return
	}
	if err = s.checkDrivePath(ctx, uint32(id), path, r.Method == http.MethodPut); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	switch {
	case listing:
		var entries any
		entries, err = s.listDrive(ctx, uint32(id), path)
		if err == nil {
			writeJSON(w, entries)
			return
		}
	case r.Method == http.MethodGet:
		var f *os.File
		f, err = os.CreateTemp("", "rdp-monitor-download-*")
		if err != nil {
			http.Error(w, "cannot buffer download", 500)
			return
		}
		defer os.Remove(f.Name())
		defer f.Close()
		event.Bytes, err = s.readDrive(ctx, uint32(id), path, f)
		if err != nil {
			break
		}
		if _, err = f.Seek(0, 0); err != nil {
			break
		}
		name := path[strings.LastIndex(path, "\\")+1:]
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		http.ServeContent(w, r, name, time.Time{}, f)
		return
	case r.Method == http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxDriveFile)
		event.Bytes, err = s.writeDrive(ctx, uint32(id), path, r.Body)
		if err == nil && event.Bytes != uint64(r.ContentLength) {
			err = errors.New("incomplete upload")
		}
		if err != nil {
			err = fmt.Errorf("upload failed; an incomplete new file may remain: %w", err)
			break
		}
		writeJSON(w, map[string]any{"bytes": event.Bytes})
		return
	case r.Method == http.MethodDelete:
		err = s.deleteDrive(ctx, uint32(id), path)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}
