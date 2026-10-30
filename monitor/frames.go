package monitor

import (
	"bytes"
	"image"
	"image/jpeg"
	"time"
)

// Screen updates are tracked as a short list of rectangles rather than one
// bounding box, so two small changes far apart do not resend the screen
// between them.
const (
	maxDirtyRects = 24
	// Rectangles are merged when their union wastes at most this share of
	// pixels compared with sending both.
	mergeSlack = 0.3
)

func area(r image.Rectangle) int { return r.Dx() * r.Dy() }

// addDirty adds r to rects, merging it with neighbours when that costs
// little and collapsing everything into one box past maxDirtyRects.
func addDirty(rects []image.Rectangle, r image.Rectangle) []image.Rectangle {
	if r.Empty() {
		return rects
	}
	for merged := true; merged; {
		merged = false
		for i, o := range rects {
			u := o.Union(r)
			if o.Overlaps(r) || float64(area(u)) <= float64(area(o)+area(r))*(1+mergeSlack) {
				r = u
				rects = append(rects[:i], rects[i+1:]...)
				merged = true
				break
			}
		}
	}
	rects = append(rects, r)
	if len(rects) > maxDirtyRects {
		u := rects[0]
		for _, o := range rects[1:] {
			u = u.Union(o)
		}
		rects = append(rects[:0], u)
	}
	return rects
}

// Rectangles whose PNG costs more than pngBudget bytes per pixel look like
// photos or video; they are sent as JPEG and re-sent losslessly once they
// have been still for refineAfter.
const (
	lossyMinPixels = 96 * 96
	pngBudget      = 1.0
	jpegQuality    = 75
	refineAfter    = 700 * time.Millisecond
)

var jpegOptions = jpeg.Options{Quality: jpegQuality}

// encodeRect returns the image bytes for img and whether they are lossy.
func encodeRect(img *image.RGBA, lossless bool) ([]byte, bool) {
	var buf bytes.Buffer
	if err := pngEncoder.Encode(&buf, img); err != nil {
		return nil, false
	}
	px := area(img.Rect)
	if lossless || px < lossyMinPixels || float64(buf.Len()) <= float64(px)*pngBudget {
		return buf.Bytes(), false
	}
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, img, &jpegOptions); err != nil || jb.Len() >= buf.Len() {
		return buf.Bytes(), false
	}
	return jb.Bytes(), true
}

type lossyRect struct {
	r    image.Rectangle
	sent time.Time
}

// noteLossy remembers r as sent lossily and forgets older lossy areas it
// covers; a changed area restarts its refine timer.
func noteLossy(list []lossyRect, r image.Rectangle, now time.Time) []lossyRect {
	return append(dropCovered(list, r), lossyRect{r: r, sent: now})
}

// dropCovered forgets lossy areas that r has just re-sent losslessly.
func dropCovered(list []lossyRect, r image.Rectangle) []lossyRect {
	out := list[:0]
	for _, l := range list {
		if !l.r.In(r) {
			out = append(out, l)
		}
	}
	return out
}

// dueRefine removes and returns the lossy areas that have not changed for
// refineAfter; dirty areas restart the timer of lossy areas they touch.
func dueRefine(list []lossyRect, dirty []image.Rectangle, now time.Time) ([]lossyRect, []image.Rectangle) {
	var due []image.Rectangle
	out := list[:0]
	for _, l := range list {
		for _, d := range dirty {
			if d.Overlaps(l.r) {
				l.sent = now
				break
			}
		}
		if now.Sub(l.sent) >= refineAfter {
			due = append(due, l.r)
			continue
		}
		out = append(out, l)
	}
	return out, due
}
