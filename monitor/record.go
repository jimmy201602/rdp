package monitor

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// A recording (.rdpv) and a live stream share one record encoding. A file
// is a header followed by records; a live WebSocket sends one record per
// binary message. Integers are little-endian.
//
//	header: "RDPV" | version u16 | metaLen u32 | meta (JSON Meta)
//	record: kind u8 | time u32 (ms since the session started) | len u32 | payload
//
// Frame and Key payloads are x, y, w, h (u16 each) followed by a PNG of that
// rectangle; Key always covers the whole screen and is a seek point. Resize
// is w, h (u16) and clears the screen; Pointer is the mouse position x, y.
const (
	RecFrame   uint8 = 1
	RecKey     uint8 = 2
	RecResize  uint8 = 3
	RecPointer uint8 = 4
	RecEnd     uint8 = 5
	RecEvent   uint8 = 6 // JSON Event; no keystroke codes or clipboard bodies
)

const (
	fileMagic      = "RDPV"
	fileVersion    = 1
	recordHeader   = 9
	maxMetaLen     = 1 << 16
	maxRecordBytes = 64 << 20
)

var ErrFormat = errors.New("monitor: bad recording")

// Meta describes a session. It is the recording header and, completed with
// the end fields, the sidecar written next to a finished recording.
type Meta struct {
	ID         string    `json:"id"`
	RemoteAddr string    `json:"remote_addr"`
	UserName   string    `json:"user"`
	Domain     string    `json:"domain,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	Target     string    `json:"target"`
	LoginForm  bool      `json:"login_form,omitempty"`
	Web        bool      `json:"web,omitempty"`
	Width      int       `json:"width"`
	Height     int       `json:"height"`
	Started    time.Time `json:"started"`

	DurationMS int64  `json:"duration_ms"`
	Size       int64  `json:"size"`
	End        string `json:"end,omitempty"`
	Error      string `json:"error,omitempty"`
	Complete   bool   `json:"complete"`
}

func encodeRecord(kind uint8, ms uint32, payload []byte) []byte {
	out := make([]byte, recordHeader, recordHeader+len(payload))
	out[0] = kind
	binary.LittleEndian.PutUint32(out[1:], ms)
	binary.LittleEndian.PutUint32(out[5:], uint32(len(payload)))
	return append(out, payload...)
}

func rectPayload(x, y, w, h int, png []byte) []byte {
	out := make([]byte, 8, 8+len(png))
	binary.LittleEndian.PutUint16(out[0:], uint16(x))
	binary.LittleEndian.PutUint16(out[2:], uint16(y))
	binary.LittleEndian.PutUint16(out[4:], uint16(w))
	binary.LittleEndian.PutUint16(out[6:], uint16(h))
	return append(out, png...)
}

func pointPayload(x, y int) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:], uint16(x))
	binary.LittleEndian.PutUint16(out[2:], uint16(y))
	return out
}

func encodeHeader(m Meta) ([]byte, error) {
	js, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 10, 10+len(js))
	copy(out, fileMagic)
	binary.LittleEndian.PutUint16(out[4:], fileVersion)
	binary.LittleEndian.PutUint32(out[6:], uint32(len(js)))
	return append(out, js...), nil
}

// Record is one decoded record.
type Record struct {
	Kind    uint8
	Time    uint32
	Payload []byte
}

// Reader decodes a recording.
type Reader struct {
	r    *bufio.Reader
	Meta Meta
}

// NewReader reads the header of a recording.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	var hdr [10]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrFormat, err)
	}
	if string(hdr[:4]) != fileMagic || binary.LittleEndian.Uint16(hdr[4:]) != fileVersion {
		return nil, fmt.Errorf("%w: not an RDPV v%d file", ErrFormat, fileVersion)
	}
	n := binary.LittleEndian.Uint32(hdr[6:])
	if n > maxMetaLen {
		return nil, fmt.Errorf("%w: meta of %d bytes", ErrFormat, n)
	}
	js := make([]byte, n)
	if _, err := io.ReadFull(br, js); err != nil {
		return nil, fmt.Errorf("%w: meta: %v", ErrFormat, err)
	}
	rd := &Reader{r: br}
	if err := json.Unmarshal(js, &rd.Meta); err != nil {
		return nil, fmt.Errorf("%w: meta: %v", ErrFormat, err)
	}
	return rd, nil
}

// Next returns the next record; io.EOF at a clean end of file and
// io.ErrUnexpectedEOF for a truncated record (a recording cut short).
func (rd *Reader) Next() (Record, error) {
	var h [recordHeader]byte
	if _, err := io.ReadFull(rd.r, h[:]); err != nil {
		return Record{}, err
	}
	n := binary.LittleEndian.Uint32(h[5:])
	if n > maxRecordBytes {
		return Record{}, fmt.Errorf("%w: record of %d bytes", ErrFormat, n)
	}
	rec := Record{Kind: h[0], Time: binary.LittleEndian.Uint32(h[1:]), Payload: make([]byte, n)}
	if _, err := io.ReadFull(rd.r, rec.Payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return Record{}, err
	}
	return rec, nil
}

// scanRecording rebuilds the metadata of a recording without a sidecar
// (the gateway stopped before the session ended).
func scanRecording(path string) (Meta, error) {
	f, err := os.Open(path)
	if err != nil {
		return Meta{}, err
	}
	defer f.Close()
	rd, err := NewReader(f)
	if err != nil {
		return Meta{}, err
	}
	m := rd.Meta
	for {
		rec, err := rd.Next()
		if err != nil {
			break
		}
		m.DurationMS = int64(rec.Time)
		if rec.Kind == RecEnd {
			m.Complete = true
		}
	}
	if st, err := f.Stat(); err == nil {
		m.Size = st.Size()
	}
	if m.End == "" && !m.Complete {
		m.End = "interrupted"
	}
	return m, nil
}

// recorder appends records to a recording file. It is used from a single
// goroutine.
type recorder struct {
	f    *os.File
	w    *bufio.Writer
	path string
	err  error
}

func createRecorder(path string, m Meta) (*recorder, error) {
	hdr, err := encodeHeader(m)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	r := &recorder{f: f, w: bufio.NewWriterSize(f, 256<<10), path: path}
	if _, err := r.w.Write(hdr); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

func (r *recorder) write(rec []byte) {
	if r.err != nil {
		return
	}
	if _, err := r.w.Write(rec); err != nil {
		r.err = err
	}
}

func (r *recorder) flush() {
	if r.err == nil {
		r.err = r.w.Flush()
	}
}

func (r *recorder) close() (int64, error) {
	r.flush()
	var size int64
	if st, err := r.f.Stat(); err == nil {
		size = st.Size()
	}
	if err := r.f.Close(); err != nil && r.err == nil {
		r.err = err
	}
	return size, r.err
}
