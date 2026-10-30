package bitmap

import (
	"bytes"
	"testing"
)

func TestPlanarRaw(t *testing.T) {
	// 2x1, no alpha, raw planes R G B and a pad byte.
	src := []byte{planarNA, 10, 20, 30, 40, 50, 60, 0}
	got, err := DecompressPlanar(src, 2, 1)
	want := []byte{50, 30, 10, 0xFF, 60, 40, 20, 0xFF}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got % x %v want % x", got, err, want)
	}
}

func TestPlanarRLE(t *testing.T) {
	src := []byte{planarNA | planarRLE,
		0x20, 10, 20, 0x20, 4, 1, // R: 10 20 / +2 -1
		0x20, 5, 5, 0x20, 0, 0, // G: 5 5 / +0 +0
		0x20, 7, 8, 0x20, 0, 0, // B: 7 8 / +0 +0
	}
	got, err := DecompressPlanar(src, 2, 2)
	want := []byte{7, 5, 10, 0xFF, 8, 5, 20, 0xFF, 7, 5, 12, 0xFF, 8, 5, 19, 0xFF}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got % x %v want % x", got, err, want)
	}
}

func TestPlanarRLERuns(t *testing.T) {
	if got, _, err := planarRLEPlane([]byte{0x13, 9}, 4, 1); err != nil || !bytes.Equal(got, []byte{9, 9, 9, 9}) {
		t.Fatalf("raw+run: % x %v", got, err)
	}
	if got, _, err := planarRLEPlane([]byte{0x21}, 18, 1); err != nil || !bytes.Equal(got, make([]byte, 18)) {
		t.Fatalf("long run: % x %v", got, err)
	}
	if _, _, err := planarRLEPlane([]byte{0x20, 1}, 2, 1); err == nil {
		t.Fatal("truncated raw values accepted")
	}
}

func TestPlanarYCoCg(t *testing.T) {
	// 1x1, color loss level 1: Y 100, Co/2 10, Cg/2 4.
	got, err := DecompressPlanar([]byte{planarNA | 1, 100, 10, 4, 0}, 1, 1)
	want := []byte{106, 104, 86, 0xFF} // B G R A: R = T - Co, B = T + Co
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got % x %v want % x", got, err, want)
	}
}

func TestDecompress32FallsBackToInterleaved(t *testing.T) {
	if got, err := decompress([]byte{0xFD}, 1, 1, 32); err != nil || !bytes.Equal(got, []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Fatalf("got % x %v", got, err)
	}
}
