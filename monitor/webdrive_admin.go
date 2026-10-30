package monitor

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/wire"
)

// A web session has no RDP client whose drives the monitor could reach;
// its only redirected drive is the owner's browser folder, served by the
// owner page itself. It is listed as device webDeviceID and the drive API
// talks to the browser directly.
const webDeviceID = 1

const webDriveChunk = 1 << 20

func (s *Session) webDevice() (Device, bool) {
	if !s.ctl.Web {
		return Device{}, false
	}
	s.mu.Lock()
	name := s.driveName
	s.mu.Unlock()
	if name == "" {
		return Device{}, false
	}
	return Device{ID: webDeviceID, Type: 0x08 /* RDPDR_DTYP_FILESYSTEM */, Name: name, Accepted: true}, true
}

// fsPath turns a drive API path ("\a\b") into a browser folder path ("a/b").
func fsPath(p string) string {
	return strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(p, `\`, "/")), "/")
}

var errNoWebFolder = errors.New("the browser folder is no longer mapped")

func (s *Session) serveWebDrive(ctx context.Context, w http.ResponseWriter, r *http.Request, device uint32, p string, listing bool, event *Event) error {
	if d, ok := s.webDevice(); !ok || d.ID != device {
		return errNoWebFolder
	}
	fs := &browserFS{s: s}
	fp := fsPath(p)
	switch {
	case listing:
		list, err := fs.List(ctx, fp)
		if err != nil {
			return err
		}
		out := make([]wire.FileEntry, 0, len(list))
		for _, e := range list {
			attr := uint32(0x80) // FILE_ATTRIBUTE_NORMAL
			if e.Dir {
				attr = 0x10 // FILE_ATTRIBUTE_DIRECTORY
			}
			out = append(out, wire.FileEntry{Name: e.Name, Size: e.Size, IsDir: e.Dir, Attributes: attr, Modified: e.Modified})
		}
		writeJSON(w, out)
		return nil
	case r.Method == http.MethodGet:
		e, err := fs.Stat(ctx, fp)
		if err != nil {
			return err
		}
		if e.Dir {
			return errors.New("is a folder")
		}
		name := path.Base(fp)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		w.Header().Set("Content-Length", strconv.FormatInt(e.Size, 10))
		for off := int64(0); off < e.Size; {
			data, err := fs.Read(ctx, fp, off, webDriveChunk)
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return io.ErrUnexpectedEOF
			}
			if _, err := w.Write(data); err != nil {
				return nil // the admin's browser went away; headers are already out
			}
			off += int64(len(data))
			event.Bytes += uint64(len(data))
		}
		return nil
	case r.Method == http.MethodPut:
		if _, err := fs.Stat(ctx, fp); err == nil {
			return gateway.FSErrExists
		} else if !errors.Is(err, gateway.FSErrNotFound) {
			return err
		}
		if err := fs.Create(ctx, fp, false); err != nil {
			return err
		}
		body := http.MaxBytesReader(w, r.Body, maxDriveFile)
		buf := make([]byte, webDriveChunk)
		for {
			n, rerr := io.ReadFull(body, buf)
			if n > 0 {
				if err := fs.Write(ctx, fp, int64(event.Bytes), buf[:n]); err != nil {
					return err
				}
				event.Bytes += uint64(n)
			}
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
		if event.Bytes != uint64(r.ContentLength) {
			return errors.New("incomplete upload")
		}
		writeJSON(w, map[string]any{"bytes": event.Bytes})
		return nil
	case r.Method == http.MethodDelete:
		e, err := fs.Stat(ctx, fp)
		if err != nil {
			return err
		}
		if e.Dir {
			return errors.New("folders are not deleted from the monitor")
		}
		if err := fs.Remove(ctx, fp); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	return errors.New("unsupported")
}
