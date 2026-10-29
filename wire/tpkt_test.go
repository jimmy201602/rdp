package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestTPKTGoldenAndFragmentation(t *testing.T) {
	payload := []byte{2, 0xf0, 0x80, 0xab}
	want := []byte{3, 0, 0, 8, 2, 0xf0, 0x80, 0xab}
	packet, err := EncodeTPKT(payload)
	if err != nil || !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, error = %v", packet, err)
	}
	r := bytes.NewReader(append(append([]byte{}, want...), want...))
	for i := 0; i < 2; i++ {
		got, err := ReadTPKT(iotest.OneByteReader(r), 1024)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("packet %d: %x, %v", i, got, err)
		}
	}
	if _, err := ReadTPKT(r, 1024); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestTPKTReadRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		max  int
		want error
	}{
		{"version", []byte{2, 0, 0, 7, 0, 0, 0}, 0, ErrTPKT},
		{"short-size", []byte{3, 0, 0, 6}, 0, ErrTPKT},
		{"over-limit-before-body", []byte{3, 0, 0xff, 0xff}, 512, ErrTPKT},
		{"invalid-limit", nil, 6, ErrTPKT},
		{"negative-limit", nil, -1, ErrTPKT},
		{"excessive-limit", nil, MaxTPKTSize + 1, ErrTPKT},
		{"truncated-header", []byte{3, 0}, 0, io.ErrUnexpectedEOF},
		{"truncated-body", []byte{3, 0, 0, 8, 1}, 0, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadTPKT(bytes.NewReader(tc.data), tc.max); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestTPKTSizeBoundaries(t *testing.T) {
	for _, size := range []int{0, 2, 3, MaxTPKTSize - TPKTHeaderSize, MaxTPKTSize - TPKTHeaderSize + 1} {
		packet, err := EncodeTPKT(make([]byte, size))
		valid := size >= 3 && size <= MaxTPKTSize-TPKTHeaderSize
		if valid != (err == nil) {
			t.Fatalf("size %d: %v", size, err)
		}
		if valid {
			got, err := ReadTPKT(bytes.NewReader(packet), 0)
			if err != nil || len(got) != size {
				t.Fatalf("size %d roundtrip: %d, %v", size, len(got), err)
			}
		}
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

type invalidWriter struct{ n int }

func (w invalidWriter) Write([]byte) (int, error) { return w.n, nil }

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestTPKTWriteHandlesShortWrites(t *testing.T) {
	payload := []byte{2, 0xf0, 0x80}
	var w shortWriter
	if err := WriteTPKT(&w, payload); err != nil {
		t.Fatal(err)
	}
	want, _ := EncodeTPKT(payload)
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("got %x, want %x", w.Bytes(), want)
	}
	for _, n := range []int{-1, 0, 100} {
		if err := WriteTPKT(invalidWriter{n}, payload); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("writer n=%d: %v", n, err)
		}
	}
	sentinel := errors.New("writer failed")
	if err := WriteTPKT(errorWriter{sentinel}, payload); !errors.Is(err, sentinel) {
		t.Fatalf("lost writer error: %v", err)
	}
	if err := WriteTPKT(&w, nil); !errors.Is(err, ErrTPKT) {
		t.Fatalf("invalid payload: %v", err)
	}
}

func FuzzReadTPKT(f *testing.F) {
	f.Add([]byte{3, 0, 0, 7, 2, 0xf0, 0x80})
	f.Add([]byte{3, 0, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := ReadTPKT(bytes.NewReader(data), 4096)
		if err != nil {
			return
		}
		if len(payload) < 3 || len(payload) > 4092 {
			t.Fatalf("unbounded payload size %d", len(payload))
		}
		encoded, err := EncodeTPKT(payload)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := ReadTPKT(bytes.NewReader(encoded), 4096)
		if err != nil || !bytes.Equal(roundtrip, payload) {
			t.Fatalf("roundtrip failed: %v", err)
		}
	})
}
