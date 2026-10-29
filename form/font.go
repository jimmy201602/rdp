package form

// RGB is an opaque colour.
type RGB struct{ R, G, B uint8 }

// Rect is a pixel rectangle in canvas coordinates.
type Rect struct{ X, Y, W, H int }

func (r Rect) contains(x, y int) bool {
	return x >= r.X && y >= r.Y && x < r.X+r.W && y < r.Y+r.H
}

func (r Rect) union(o Rect) Rect {
	if r.W == 0 || r.H == 0 {
		return o
	}
	if o.W == 0 || o.H == 0 {
		return r
	}
	x0, y0 := min(r.X, o.X), min(r.Y, o.Y)
	x1, y1 := max(r.X+r.W, o.X+o.W), max(r.Y+r.H, o.Y+o.H)
	return Rect{x0, y0, x1 - x0, y1 - y0}
}

// Canvas is a top-down 24bpp BGR bitmap, the layout server.Frame uses.
type Canvas struct {
	Width, Height int
	BGR           []byte
}

func newCanvas(w, h int) *Canvas {
	return &Canvas{Width: w, Height: h, BGR: make([]byte, w*h*3)}
}

func (c *Canvas) set(x, y int, col RGB) {
	if x < 0 || y < 0 || x >= c.Width || y >= c.Height {
		return
	}
	i := (y*c.Width + x) * 3
	c.BGR[i], c.BGR[i+1], c.BGR[i+2] = col.B, col.G, col.R
}

func (c *Canvas) fill(r Rect, col RGB) {
	x0, y0 := max(r.X, 0), max(r.Y, 0)
	x1, y1 := min(r.X+r.W, c.Width), min(r.Y+r.H, c.Height)
	if x0 >= x1 || y0 >= y1 {
		return
	}
	row := make([]byte, (x1-x0)*3)
	for i := 0; i < len(row); i += 3 {
		row[i], row[i+1], row[i+2] = col.B, col.G, col.R
	}
	for y := y0; y < y1; y++ {
		copy(c.BGR[(y*c.Width+x0)*3:], row)
	}
}

func (c *Canvas) outline(r Rect, col RGB, t int) {
	c.fill(Rect{r.X, r.Y, r.W, t}, col)
	c.fill(Rect{r.X, r.Y + r.H - t, r.W, t}, col)
	c.fill(Rect{r.X, r.Y, t, r.H}, col)
	c.fill(Rect{r.X + r.W - t, r.Y, t, r.H}, col)
}

// glyphHeight is the unscaled height of every glyph in the font.
const glyphHeight = 16

// glyph returns the 1bpp bitmap and unscaled advance (8 or 16 px) of r,
// substituting U+FFFD for runes outside the embedded subset.
func glyph(r rune) ([]byte, int) {
	g, ok := unifontGlyphs[r]
	if !ok {
		g = unifontGlyphs[0xFFFD]
	}
	return g, len(g) / glyphHeight * 8
}

func hasGlyph(r rune) bool {
	_, ok := unifontGlyphs[r]
	return ok
}

func runeWidth(r rune, scale int) int {
	_, adv := glyph(r)
	return adv * scale
}

func textWidth(s []rune, scale int) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r, scale)
	}
	return w
}

// drawText renders s with its top-left corner at (x, y) and returns the
// advance in pixels. Only set pixels are painted, so the caller clears the
// background first.
func (c *Canvas) drawText(x, y int, s []rune, scale int, col RGB) int {
	x0 := x
	for _, r := range s {
		g, adv := glyph(r)
		bytesPerRow := adv / 8
		for row := 0; row < glyphHeight; row++ {
			for bx := 0; bx < adv; bx++ {
				if g[row*bytesPerRow+bx/8]&(0x80>>(bx%8)) == 0 {
					continue
				}
				if scale == 1 {
					c.set(x+bx, y+row, col)
				} else {
					c.fill(Rect{x + bx*scale, y + row*scale, scale, scale}, col)
				}
			}
		}
		x += adv * scale
	}
	return x - x0
}
