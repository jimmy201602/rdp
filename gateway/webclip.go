package gateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

	"rdp.local/kernel/wire"
)

// ClipContent is one clipboard snapshot exchanged with a web session's
// browser. Any field may be empty; PNG holds a PNG-encoded image.
type ClipContent struct {
	Text string
	HTML string
	PNG  []byte
}

func (c ClipContent) empty() bool { return c.Text == "" && c.HTML == "" && len(c.PNG) == 0 }

// ClipboardObserver is implemented by Observers of web sessions that want
// what the remote desktop copied (the browser is the clipboard owner).
type ClipboardObserver interface {
	RemoteClipboard(c ClipContent)
}

const (
	maxClipText  = 1 << 20
	maxClipHTML  = 2 << 20
	maxClipImage = wire.MaxChannelMessage

	cfDIB   = 8
	cfDIBV5 = 17
	// IDs this client gives its registered formats in its format lists.
	cfLocalHTML = 0xC0A1
	cfLocalPNG  = 0xC0A2
)

type clipKind int

const (
	clipText clipKind = iota
	clipHTML
	clipPNG
	clipDIB
)

type clipRequest struct {
	kind clipKind
	id   uint32
}

// webClip is the client side of cliprdr for a web session: text, HTML and
// images in both directions.
type webClip struct {
	send      func([]byte) error
	onText    func(ClipContent)
	mu        sync.Mutex
	ready     bool
	longNames bool
	local     ClipContent // what the browser offered, served on Format Data Request
	hasLocal  bool

	// Remote -> browser: the Format Data Requests still to send for the
	// current remote format list, one outstanding at a time.
	pending  []clipRequest
	asking   *clipRequest
	stale    int // responses still due for requests of a superseded list
	incoming ClipContent
}

func clipPDU(msgType, flags uint16, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint16(b, msgType)
	binary.LittleEndian.PutUint16(b[2:], flags)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	return append(b, body...)
}

func utf16le(s string, z bool) []byte {
	u := utf16.Encode([]rune(s))
	if z {
		u = append(u, 0)
	}
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func fromUTF16le(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

func (c *webClip) appendFormat(body []byte, id uint32, name string) []byte {
	body = binary.LittleEndian.AppendUint32(body, id)
	if c.longNames {
		return append(body, utf16le(name, true)...)
	}
	short := make([]byte, 32)
	copy(short[:30], utf16le(name, false))
	return append(body, short...)
}

func (c *webClip) formatList() []byte {
	var body []byte
	if c.hasLocal {
		if c.local.Text != "" {
			body = c.appendFormat(body, wire.CFUnicodeText, "")
		}
		if c.local.HTML != "" {
			body = c.appendFormat(body, cfLocalHTML, "HTML Format")
		}
		if len(c.local.PNG) > 0 {
			body = c.appendFormat(body, cfLocalPNG, "PNG")
			body = c.appendFormat(body, cfDIB, "")
		}
	}
	return clipPDU(wire.CBFormatList, 0, body)
}

// remoteRequests picks the formats to fetch from a remote format list.
func remoteRequests(formats []wire.ClipFormat) []clipRequest {
	var text, html, img *clipRequest
	for _, f := range formats {
		switch {
		case f.ID == wire.CFUnicodeText:
			text = &clipRequest{clipText, f.ID}
		case f.ID == wire.CFText && text == nil:
			text = &clipRequest{clipText, f.ID}
		case f.Name == "HTML Format":
			html = &clipRequest{clipHTML, f.ID}
		case f.Name == "PNG":
			img = &clipRequest{clipPNG, f.ID}
		case (f.ID == cfDIB || f.ID == cfDIBV5) && (img == nil || img.kind != clipPNG):
			if img == nil || f.ID == cfDIB {
				img = &clipRequest{clipDIB, f.ID}
			}
		}
	}
	var out []clipRequest
	for _, r := range []*clipRequest{text, html, img} {
		if r != nil {
			out = append(out, *r)
		}
	}
	return out
}

// next sends the following queued request, or hands the collected content
// to the observer once the queue is empty.
func (c *webClip) next() error {
	if len(c.pending) == 0 {
		c.asking = nil
		in := c.incoming
		c.incoming = ClipContent{}
		if !in.empty() && c.onText != nil {
			go c.onText(in)
		}
		return nil
	}
	r := c.pending[0]
	c.pending = c.pending[1:]
	c.asking = &r
	return c.send(clipPDU(wire.CBFormatDataRequest, 0, binary.LittleEndian.AppendUint32(nil, r.id)))
}

func (c *webClip) localData(id uint32) ([]byte, bool) {
	switch id {
	case wire.CFUnicodeText:
		return utf16le(c.local.Text, true), c.local.Text != ""
	case wire.CFText:
		return append([]byte(c.local.Text), 0), c.local.Text != ""
	case cfLocalHTML:
		return append(encodeCFHTML(c.local.HTML), 0), c.local.HTML != ""
	case cfLocalPNG:
		return c.local.PNG, len(c.local.PNG) > 0
	case cfDIB:
		if len(c.local.PNG) == 0 {
			return nil, false
		}
		dib, err := pngToDIB(c.local.PNG)
		return dib, err == nil
	}
	return nil, false
}

// handle processes one reassembled message from the server.
func (c *webClip) handle(msg []byte) error {
	h, body, err := wire.DecodeClipHeader(msg)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch h.MsgType {
	case wire.CBClipCaps:
		// cCapabilitiesSets u16, pad u16, then CLIPRDR_GENERAL_CAPABILITY.
		if len(body) >= 16 && binary.LittleEndian.Uint16(body[4:]) == 1 {
			c.longNames = binary.LittleEndian.Uint32(body[12:])&0x02 != 0
		}
	case wire.CBMonitorReady:
		caps := make([]byte, 16)
		binary.LittleEndian.PutUint16(caps, 1)
		binary.LittleEndian.PutUint16(caps[4:], 1)  // CB_CAPSTYPE_GENERAL
		binary.LittleEndian.PutUint16(caps[6:], 12) // lengthCapability
		binary.LittleEndian.PutUint32(caps[8:], 2)  // CB_CAPS_VERSION_2
		var flags uint32
		if c.longNames {
			flags = 0x02 // CB_USE_LONG_FORMAT_NAMES
		}
		binary.LittleEndian.PutUint32(caps[12:], flags)
		if err := c.send(clipPDU(wire.CBClipCaps, 0, caps)); err != nil {
			return err
		}
		c.ready = true
		return c.send(c.formatList())
	case wire.CBFormatList:
		if err := c.send(clipPDU(wire.CBFormatListResponse, wire.CBResponseOK, nil)); err != nil {
			return err
		}
		c.hasLocal = false
		if c.asking != nil {
			c.stale++
		}
		c.pending = remoteRequests(wire.DecodeFormatList(body, c.longNames && h.MsgFlags&wire.CBASCIINames == 0))
		c.incoming = ClipContent{}
		c.asking = nil
		if c.stale == 0 {
			return c.next()
		}
	case wire.CBFormatDataRequest:
		id, _ := wire.DecodeFormatDataRequest(body)
		data, ok := c.localData(id)
		if !c.hasLocal || !ok {
			return c.send(clipPDU(wire.CBFormatDataResponse, wire.CBResponseFail, nil))
		}
		return c.send(clipPDU(wire.CBFormatDataResponse, wire.CBResponseOK, data))
	case wire.CBFormatDataResponse:
		if c.stale > 0 {
			c.stale--
			if c.stale == 0 && c.asking == nil {
				return c.next()
			}
			return nil
		}
		if c.asking == nil {
			return nil
		}
		if h.MsgFlags&wire.CBResponseOK != 0 {
			c.store(*c.asking, body)
		}
		return c.next()
	}
	return nil
}

func (c *webClip) store(r clipRequest, body []byte) {
	switch r.kind {
	case clipText:
		if r.id == wire.CFText {
			if i := bytes.IndexByte(body, 0); i >= 0 {
				body = body[:i]
			}
			if len(body) <= maxClipText {
				c.incoming.Text = string(body)
			}
		} else if len(body) <= 2*maxClipText {
			c.incoming.Text = fromUTF16le(body)
		}
	case clipHTML:
		if len(body) <= maxClipHTML {
			c.incoming.HTML = decodeCFHTML(body)
		}
	case clipPNG:
		if len(body) <= maxClipImage {
			c.incoming.PNG = append([]byte(nil), body...)
		}
	case clipDIB:
		if p, err := dibToPNG(body); err == nil {
			c.incoming.PNG = p
		}
	}
}

// set offers browser clipboard content to the remote desktop.
func (c *webClip) set(in ClipContent) error {
	if len(in.Text) > maxClipText {
		in.Text = in.Text[:maxClipText]
	}
	if len(in.HTML) > maxClipHTML {
		in.HTML = ""
	}
	if len(in.PNG) > maxClipImage {
		in.PNG = nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.local, c.hasLocal = in, !in.empty()
	if !c.ready {
		return nil
	}
	return c.send(c.formatList())
}

// encodeCFHTML wraps an HTML fragment in the Windows "HTML Format" header,
// whose offsets count UTF-8 bytes from the start of the data.
func encodeCFHTML(fragment string) []byte {
	const hdr = "Version:0.9\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n"
	const pre, post = "<html><body>\r\n<!--StartFragment-->", "<!--EndFragment-->\r\n</body>\r\n</html>"
	n := len(fmt.Sprintf(hdr, 0, 0, 0, 0))
	startFrag := n + len(pre)
	endFrag := startFrag + len(fragment)
	end := endFrag + len(post)
	return []byte(fmt.Sprintf(hdr, n, end, startFrag, endFrag) + pre + fragment + post)
}

func decodeCFHTML(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	s := string(b)
	off := func(key string) int {
		i := strings.Index(s, key+":")
		if i < 0 {
			return -1
		}
		j := i + len(key) + 1
		k := j
		for k < len(s) && (s[k] == '-' || s[k] >= '0' && s[k] <= '9') {
			k++
		}
		v, err := strconv.Atoi(s[j:k])
		if err != nil {
			return -1
		}
		return v
	}
	for _, p := range [][2]string{{"StartFragment", "EndFragment"}, {"StartHTML", "EndHTML"}} {
		a, z := off(p[0]), off(p[1])
		if a >= 0 && z > a && z <= len(s) {
			return s[a:z]
		}
	}
	if i := strings.Index(s, "<"); i >= 0 {
		return s[i:]
	}
	return s
}

var errDIB = errors.New("unsupported DIB")

// dibToPNG converts a CF_DIB / CF_DIBV5 (16, 24 or 32 bpp; BI_RGB, or
// BI_BITFIELDS with 5-5-5 / 5-6-5 masks at 16 bpp and BGRA masks at 32) to PNG.
func dibToPNG(b []byte) ([]byte, error) {
	if len(b) < 40 {
		return nil, errDIB
	}
	hsize := int(binary.LittleEndian.Uint32(b))
	w := int(int32(binary.LittleEndian.Uint32(b[4:])))
	h := int(int32(binary.LittleEndian.Uint32(b[8:])))
	bpp := int(binary.LittleEndian.Uint16(b[14:]))
	comp := binary.LittleEndian.Uint32(b[16:])
	clrUsed := int(binary.LittleEndian.Uint32(b[32:]))
	if hsize < 40 || hsize > len(b) || w <= 0 || w > 16384 || h == 0 || h > 16384 || h < -16384 {
		return nil, errDIB
	}
	if (bpp != 16 && bpp != 24 && bpp != 32) || (comp != 0 && comp != 3) || clrUsed > 256 {
		return nil, errDIB
	}
	off := hsize + 4*clrUsed
	if comp == 3 && hsize == 40 {
		off += 12
	}
	rgb565 := false
	if bpp == 16 && comp == 3 {
		// The red mask follows the 40-byte header fields in both layouts.
		if 44 > len(b) {
			return nil, errDIB
		}
		rgb565 = binary.LittleEndian.Uint32(b[40:]) == 0xF800
	}
	topDown := h < 0
	if topDown {
		h = -h
	}
	stride := (w*bpp/8 + 3) &^ 3
	if off+stride*h > len(b) {
		return nil, errDIB
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	alpha := false
	if bpp == 32 && comp == 0 {
		for y := 0; y < h && !alpha; y++ {
			row := b[off+y*stride:]
			for x := 0; x < w; x++ {
				if row[4*x+3] != 0 {
					alpha = true
					break
				}
			}
		}
	}
	px := bpp / 8
	for y := 0; y < h; y++ {
		sy := h - 1 - y
		if topDown {
			sy = y
		}
		row := b[off+sy*stride:]
		for x := 0; x < w; x++ {
			p := row[px*x:]
			if bpp == 16 {
				v := uint32(binary.LittleEndian.Uint16(p))
				var r, g, bl uint32
				if rgb565 {
					r, g, bl = v>>11&0x1f, v>>5&0x3f, v&0x1f
					img.SetNRGBA(x, y, color.NRGBA{R: uint8(r<<3 | r>>2), G: uint8(g<<2 | g>>4), B: uint8(bl<<3 | bl>>2), A: 255})
				} else {
					r, g, bl = v>>10&0x1f, v>>5&0x1f, v&0x1f
					img.SetNRGBA(x, y, color.NRGBA{R: uint8(r<<3 | r>>2), G: uint8(g<<3 | g>>2), B: uint8(bl<<3 | bl>>2), A: 255})
				}
				continue
			}
			a := uint8(255)
			if alpha {
				a = p[3]
			}
			img.SetNRGBA(x, y, color.NRGBA{R: p[2], G: p[1], B: p[0], A: a})
		}
	}
	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// pngToDIB converts a PNG to a bottom-up 32 bpp BI_RGB CF_DIB.
func pngToDIB(p []byte) ([]byte, error) {
	cfg, err := png.DecodeConfig(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	if cfg.Width*cfg.Height*4 > maxClipImage {
		return nil, errDIB
	}
	img, err := png.Decode(bytes.NewReader(p))
	if err != nil {
		return nil, err
	}
	r := img.Bounds()
	w, h := r.Dx(), r.Dy()
	out := make([]byte, 40, 40+4*w*h)
	binary.LittleEndian.PutUint32(out, 40)
	binary.LittleEndian.PutUint32(out[4:], uint32(w))
	binary.LittleEndian.PutUint32(out[8:], uint32(h))
	binary.LittleEndian.PutUint16(out[12:], 1)
	binary.LittleEndian.PutUint16(out[14:], 32)
	binary.LittleEndian.PutUint32(out[20:], uint32(4*w*h))
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := color.NRGBAModel.Convert(img.At(r.Min.X+x, r.Min.Y+y)).(color.NRGBA)
			out = append(out, c.B, c.G, c.R, c.A)
		}
	}
	return out, nil
}
