package monitor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"rdp.local/kernel/gateway"
	"rdp.local/kernel/wire"
)

func TestDrivePathBoundaries(t *testing.T) {
	for in, want := range map[string]string{"": "\\", "/": "\\", "/docs/a.txt": "\\docs\\a.txt", "docs\\a.txt": "\\docs\\a.txt"} {
		if got, err := drivePath(in); err != nil || got != want {
			t.Errorf("drivePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"../x", "/a/../b", "/a/./b", "//server/share", "C:/x", "/x::$DATA", "/a*", "/a?", "/a.", "/a ", "/a\x00b", "/a//b", "/a|b"} {
		if got, err := drivePath(in); err == nil {
			t.Errorf("drivePath(%q) accepted as %q", in, got)
		}
	}
}

func TestDriveHTTPRequiresBearerAndSwitch(t *testing.T) {
	const url = "/api/sessions/missing/drives/1/entries?path=/"
	for _, tc := range []struct {
		name   string
		enable bool
		url    string
		auth   string
		want   int
	}{
		{"no token", true, url, "", http.StatusUnauthorized},
		{"query token", true, url + "&token=tok", "", http.StatusUnauthorized},
		{"switch off", false, url, "Bearer tok", http.StatusForbidden},
		{"wrong token", true, url, "Bearer wrong", http.StatusUnauthorized},
		{"empty bearer", true, url, "Bearer ", http.StatusUnauthorized},
		{"basic auth", true, url + "&token=tok", "Basic tok", http.StatusUnauthorized},
		{"wrong bearer with valid query", true, url + "&token=tok", "Bearer wrong", http.StatusUnauthorized},
		{"allowed", true, url, "Bearer tok", http.StatusNotFound},
	} {
		m, err := New(Config{AllowDriveControl: tc.enable})
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			path := tc.url
			if method != http.MethodGet {
				path = strings.Replace(path, "/entries?", "/file?", 1)
			}
			req := httptest.NewRequest(method, path, nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			m.Handler("tok", "").ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("%s %s: status %d, want %d", tc.name, method, rec.Code, tc.want)
			}
		}
	}
}

func driveTestSession(t *testing.T, request func(context.Context, []byte) (wire.IOCompletion, error)) *Session {
	t.Helper()
	m, err := New(Config{AllowDriveControl: true})
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{m: m, audit: newAudit(), done: make(chan struct{}), ctl: gateway.ObserveSession{DriveRequest: request}}
	s.audit.devices[5] = Device{ID: 5, Type: wire.RDPDRDtypFilesystem, Accepted: true}
	m.sessions["test"] = s
	return s
}

func TestDriveHTTPRejectsBeforeIO(t *testing.T) {
	s := driveTestSession(t, func(context.Context, []byte) (wire.IOCompletion, error) {
		t.Error("rejected request reached mapped device")
		return wire.IOCompletion{}, errors.New("unexpected IO")
	})
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		for _, tc := range []struct {
			path, device string
			want         int
		}{
			{"/", "5", 400}, {"../escape", "5", 400}, {"//server/share", "5", 400},
			{"/file", "invalid", 400}, {"/file", "4294967296", 400}, {"/file", "99", 409},
		} {
			req := httptest.NewRequest(method, "/api/sessions/test/drives/"+tc.device+"/file?path="+url.QueryEscape(tc.path), strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer tok")
			rec := httptest.NewRecorder()
			s.m.Handler("tok", "").ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("%s %q %s: status %d, want %d", method, tc.path, tc.device, rec.Code, tc.want)
			}
		}
	}
	for _, length := range []int64{-1, maxDriveFile + 1} {
		req := httptest.NewRequest(http.MethodPut, "/api/sessions/test/drives/5/file?path=/file", strings.NewReader(""))
		req.ContentLength = length
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		s.m.Handler("tok", "").ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("length %d: status %d", length, rec.Code)
		}
	}
}

func TestDriveAvailabilityAndInfo(t *testing.T) {
	s := driveTestSession(t, func(context.Context, []byte) (wire.IOCompletion, error) {
		t.Error("unavailable device reached IO")
		return wire.IOCompletion{}, errors.New("unexpected IO")
	})
	for _, d := range []Device{{ID: 5, Type: wire.RDPDRDtypFilesystem}, {ID: 5, Type: 4, Accepted: true}} {
		s.audit.devices[5] = d
		if _, err := s.openDrive(context.Background(), 5, "\\", wire.AccessListDir, wire.FileOpen, wire.OptionsDir); err == nil {
			t.Fatalf("accepted unavailable device %+v", d)
		}
	}
	for _, enabled := range []bool{false, true} {
		for _, token := range []string{"", "tok"} {
			s.m.cfg.AllowDriveControl = enabled
			h := s.m.Handler(token, "")
			for _, path := range []string{"/api/info", "/api/sessions/test/devices", "/api/sessions/test/drives/5/entries"} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				want := http.StatusOK
				if strings.HasSuffix(path, "/entries") {
					want = http.StatusForbidden
					if enabled && token != "" {
						want = http.StatusBadGateway
					}
				}
				if rec.Code != want {
					t.Fatalf("enabled=%v token=%v %s: %d, want %d", enabled, token != "", path, rec.Code, want)
				}
				if path == "/api/info" {
					var info struct {
						DriveControl bool `json:"drive_control"`
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
						t.Fatal(err)
					}
					if info.DriveControl != (enabled && token != "") {
						t.Fatalf("incorrect drive_control: %+v", info)
					}
				}
			}
		}
	}
}

func TestDriveOperationsCloseHandles(t *testing.T) {
	operations := map[string]func(*Session, context.Context) error{
		"list": func(s *Session, ctx context.Context) error { _, err := s.listDrive(ctx, 5, "\\"); return err },
		"read": func(s *Session, ctx context.Context) error {
			_, err := s.readDrive(ctx, 5, "\\file", io.Discard)
			return err
		},
		"write": func(s *Session, ctx context.Context) error {
			_, err := s.writeDrive(ctx, 5, "\\file", strings.NewReader("payload"))
			return err
		},
		"delete": func(s *Session, ctx context.Context) error { return s.deleteDrive(ctx, 5, "\\file") },
	}
	closeErr := errors.New("close failed")
	for name, operation := range operations {
		for _, mode := range []string{"success", "cancel", "close error"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				opens, closes := 0, 0
				s := driveTestSession(t, func(callCtx context.Context, p []byte) (wire.IOCompletion, error) {
					r, err := wire.DecodeIORequest(p[4:])
					if err != nil {
						t.Fatal(err)
					}
					if r.DeviceID != 5 {
						t.Fatalf("wrong device: %+v", r)
					}
					if r.Major == wire.IRPMJCreate {
						opens++
						if binary.LittleEndian.Uint32(p[48:])&0x00200000 == 0 {
							t.Fatal("missing OPEN_REPARSE_POINT")
						}
						if name == "write" && r.CreateDisposition != wire.FileCreate {
							t.Fatal("upload can overwrite existing file")
						}
						return wire.IOCompletion{Tail: le32(77)}, nil
					}
					if r.FileID != 77 {
						t.Fatalf("wrong handle: %+v", r)
					}
					if r.Major == wire.IRPMJClose {
						closes++
						if callCtx.Err() != nil {
							t.Fatal("close reused canceled context")
						}
						if mode == "close error" {
							return wire.IOCompletion{}, closeErr
						}
						return wire.IOCompletion{}, nil
					}
					if mode == "cancel" {
						cancel()
						return wire.IOCompletion{}, callCtx.Err()
					}
					switch r.Major {
					case wire.IRPMJDirectoryControl:
						return wire.IOCompletion{IoStatus: wire.StatusNoMoreFiles}, nil
					case wire.IRPMJRead:
						return wire.IOCompletion{Tail: le32(0)}, nil
					case wire.IRPMJWrite:
						return wire.IOCompletion{Tail: le32(r.Length)}, nil
					case wire.IRPMJSetInformation:
						return wire.IOCompletion{}, nil
					default:
						t.Fatalf("unexpected request %+v", r)
						return wire.IOCompletion{}, nil
					}
				})
				err := operation(s, ctx)
				if mode == "success" && err != nil {
					t.Fatal(err)
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
				if mode == "close error" && !errors.Is(err, closeErr) {
					t.Fatalf("got %v", err)
				}
				if opens != 1 || closes != 1 {
					t.Fatalf("opens=%d closes=%d", opens, closes)
				}
			})
		}
	}
}

func TestCheckDrivePathRejectsReparseAndOverwrite(t *testing.T) {
	for _, tc := range []struct {
		name, path     string
		attrs          uint32
		create, reject bool
	}{
		{"file", "\\entry", 0, false, false},
		{"new file", "\\new", 0, true, false},
		{"missing file", "\\new", 0, false, true},
		{"overwrite", "\\entry", 0, true, true},
		{"case insensitive overwrite", "\\ENTRY", 0, true, true},
		{"final symlink", "\\entry", 0x400, false, true},
		{"parent junction", "\\entry\\child", 0x410, false, true},
		{"parent junction on create", "\\entry\\new", 0x410, true, true},
		{"parent is file", "\\entry\\child", 0, false, true},
		{"missing parent", "\\missing\\new", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closes, queries := 0, 0
			s := driveTestSession(t, func(_ context.Context, p []byte) (wire.IOCompletion, error) {
				r, err := wire.DecodeIORequest(p[4:])
				if err != nil {
					t.Fatal(err)
				}
				switch r.Major {
				case wire.IRPMJCreate:
					if r.Path != "\\" {
						t.Fatalf("opened unsafe parent %q", r.Path)
					}
					return wire.IOCompletion{Tail: le32(77)}, nil
				case wire.IRPMJClose:
					closes++
					return wire.IOCompletion{}, nil
				case wire.IRPMJDirectoryControl:
					queries++
					if queries > 1 {
						return wire.IOCompletion{IoStatus: wire.StatusNoMoreFiles}, nil
					}
					name := utf16.Encode([]rune("entry"))
					entry := make([]byte, 64+len(name)*2)
					binary.LittleEndian.PutUint32(entry[56:], tc.attrs)
					binary.LittleEndian.PutUint32(entry[60:], uint32(len(name)*2))
					for i, ch := range name {
						binary.LittleEndian.PutUint16(entry[64+i*2:], ch)
					}
					return wire.IOCompletion{Tail: append(le32(uint32(len(entry))), entry...)}, nil
				default:
					t.Fatalf("unexpected request %+v", r)
					return wire.IOCompletion{}, nil
				}
			})
			err := s.checkDrivePath(context.Background(), 5, tc.path, tc.create)
			if (err != nil) != tc.reject {
				t.Fatalf("got %v, reject=%v", err, tc.reject)
			}
			if closes != 1 {
				t.Fatalf("closed %d directory handles", closes)
			}
		})
	}
}

func rdpdrMessage(packet uint16, body ...[]byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out, wire.RDPDRCtypCore)
	binary.LittleEndian.PutUint16(out[2:], packet)
	for _, b := range body {
		out = append(out, b...)
	}
	return out
}

func le32(values ...uint32) []byte {
	out := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}

func drainEvents(s *Session) []Event {
	var out []Event
	for {
		select {
		case e := <-s.audit.queue:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestAuditEventsRecordedAndBroadcast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.rdpv")
	rec, err := createRecorder(path, Meta{ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.f.Close() })
	v := &viewer{out: make(chan []byte, 16)}
	s := &Session{audit: newAudit(), start: time.Now(), rec: rec, viewers: map[*viewer]struct{}{v: {}}}
	s.inputEvents([]wire.InputEvent{
		{Kind: wire.InputKindScancode, Code: 30},
		{Kind: wire.InputKindMouse, Flags: 0x0800, X: 12, Y: 24},
		{Kind: wire.InputKindMouse, Flags: 0x0800, X: 13, Y: 25},
		{Kind: wire.InputKindMouse, Flags: 0x9000},
		{Kind: wire.InputKindMouse, Flags: 0x1000},
		{Kind: wire.InputKindMouse, Flags: 0x0200},
	}, "client")
	s.flushEvents()
	if _, err := rec.close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var last uint32
	for _, action := range []string{"input", "move", "button_down", "button_up", "wheel"} {
		r, err := rd.Next()
		if err != nil {
			t.Fatal(err)
		}
		if r.Kind != RecEvent || r.Time < last {
			t.Fatalf("invalid event record: %+v", r)
		}
		last = r.Time
		var event Event
		if err := json.Unmarshal(r.Payload, &event); err != nil {
			t.Fatal(err)
		}
		if event.Action != action {
			t.Fatalf("got %q, want %q", event.Action, action)
		}
		select {
		case live := <-v.out:
			if string(live) != string(encodeRecord(r.Kind, r.Time, r.Payload)) {
				t.Fatal("live/recording event mismatch")
			}
		default:
			t.Fatal("event not broadcast")
		}
	}
	if _, err := rd.Next(); err != io.EOF {
		t.Fatalf("mouse moves not sampled: %v", err)
	}
	if len(v.out) != 0 {
		t.Fatal("unexpected extra live events")
	}
}

func TestAuditEventsTrackFilesWithoutContent(t *testing.T) {
	s := &Session{audit: newAudit()}
	dos := make([]byte, 8)
	copy(dos, "D:")
	s.ClientChannel("rdpdr", rdpdrMessage(wire.PakidCoreDevicelistAnnounce, le32(1, wire.RDPDRDtypFilesystem, 5), dos, le32(0)))
	s.ServerChannel("rdpdr", wire.EncodeCreate(5, 1, "\\secret.txt", wire.AccessReadFile, wire.FileOpen, wire.OptionsFile))
	s.ClientChannel("rdpdr", rdpdrMessage(wire.PakidCoreDeviceIOCompletion, le32(5, 1, 0, 9), []byte{1}))
	s.ServerChannel("rdpdr", wire.EncodeRead(5, 9, 2, 64, 0))
	s.ClientChannel("rdpdr", rdpdrMessage(wire.PakidCoreDeviceIOCompletion, le32(5, 2, 0, 4), []byte("BODY")))

	clip := make([]byte, 8)
	binary.LittleEndian.PutUint16(clip, wire.CBFormatDataResponse)
	binary.LittleEndian.PutUint16(clip[2:], wire.CBResponseOK)
	binary.LittleEndian.PutUint32(clip[4:], 15)
	s.ClientChannel("cliprdr", append(clip, []byte("clipboard-pass!")...))
	s.inputEvents([]wire.InputEvent{{Kind: wire.InputKindUnicode, Code: 'p'}}, "client")

	events := drainEvents(s)
	if len(events) != 5 {
		t.Fatalf("events %+v", events)
	}
	if e := events[2]; e.Action != "read_upload" || e.Path != "\\secret.txt" || e.Bytes != 4 {
		t.Fatalf("read event %+v", e)
	}
	if e := events[3]; e.Kind != "clipboard" || e.Bytes != 15 {
		t.Fatalf("clipboard event %+v", e)
	}
	js, _ := json.Marshal(events)
	for _, leaked := range []string{"BODY", "clipboard-pass", `"code"`} {
		if strings.Contains(string(js), leaked) {
			t.Fatalf("event JSON leaked %q: %s", leaked, js)
		}
	}
}
