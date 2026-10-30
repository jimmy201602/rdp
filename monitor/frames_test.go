package monitor

import (
	"image"
	"image/color"
	"math/rand"
	"testing"
	"time"
)

func TestAddDirtyKeepsDistantRectsApart(t *testing.T) {
	var d []image.Rectangle
	d = addDirty(d, image.Rect(0, 0, 10, 10))
	d = addDirty(d, image.Rect(1000, 700, 1010, 710))
	if len(d) != 2 {
		t.Fatalf("got %v", d)
	}
	d = addDirty(d, image.Rect(5, 5, 20, 20)) // overlaps the first
	if len(d) != 2 || d[1] != image.Rect(0, 0, 20, 20) {
		t.Fatalf("got %v", d)
	}
	for i := 0; i < 100; i++ {
		d = addDirty(d, image.Rect(i*40, 300, i*40+2, 302))
	}
	if len(d) > maxDirtyRects {
		t.Fatalf("%d rects", len(d))
	}
}

func TestEncodeRectPicksJPEGForNoise(t *testing.T) {
	flat := image.NewRGBA(image.Rect(0, 0, 200, 200))
	for i := range flat.Pix {
		flat.Pix[i] = 0xff
	}
	if _, lossy := encodeRect(flat, false); lossy {
		t.Fatal("flat area sent lossy")
	}
	noise := image.NewRGBA(image.Rect(0, 0, 200, 200))
	rng := rand.New(rand.NewSource(1))
	for y := 0; y < 200; y++ {
		for x := 0; x < 200; x++ {
			noise.Set(x, y, color.RGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 0xff})
		}
	}
	if _, lossy := encodeRect(noise, false); !lossy {
		t.Fatal("noisy area sent as PNG")
	}
	if _, lossy := encodeRect(noise, true); lossy {
		t.Fatal("lossless request ignored")
	}
}

func TestRefineAfterStill(t *testing.T) {
	now := time.Now()
	r := image.Rect(0, 0, 100, 100)
	l := noteLossy(nil, r, now)
	l, due := dueRefine(l, nil, now.Add(100*time.Millisecond))
	if len(due) != 0 || len(l) != 1 {
		t.Fatal("refined too early")
	}
	l, due = dueRefine(l, []image.Rectangle{image.Rect(50, 50, 60, 60)}, now.Add(600*time.Millisecond))
	if len(due) != 0 {
		t.Fatal("changing area refined")
	}
	l, due = dueRefine(l, nil, now.Add(600*time.Millisecond+refineAfter))
	if len(due) != 1 || len(l) != 0 {
		t.Fatalf("due %v left %v", due, l)
	}
}
