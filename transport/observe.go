package transport

import (
	"errors"
	"fmt"
	"image/color"
	"io"
	"net"
	"time"

	"rdp.local/kernel/bitmap"
	"rdp.local/kernel/wire"
)

// Observation summarises the server output read after Font Map, over both
// slow-path (Share Data) and fast-path PDUs. Bitmaps are counted and
// length-checked and, with Options.Render, decoded into Result.Framebuffer
// and pointers into Result.Pointer; orders are not parsed.
type Observation struct {
	Duration time.Duration `json:"duration_ns"`
	// End tells why observation stopped: "timeout" (Options.Observe
	// elapsed), "closed" (server closed the connection or sent
	// DisconnectProviderUltimatum) or "error".
	End string `json:"end"`

	PDUs            int            `json:"pdus"`          // slow-path + fast-path PDUs
	FastPathPDUs    int            `json:"fastpath_pdus"` // TS_FP_UPDATE_PDUs among PDUs
	FastPathUpdates map[string]int `json:"fastpath_updates,omitempty"`
	Fragments       int            `json:"fragments"`         // fast-path updates reassembled from fragments
	Updates         map[string]int `json:"updates,omitempty"` // "bitmap", "orders", "palette", "synchronize" (both paths)
	BitmapRects     int            `json:"bitmap_rects"`
	BitmapBytes     int            `json:"bitmap_bytes"`
	Compressed      int            `json:"compressed_rects"` // compressed rectangles among BitmapRects
	Orders          int            `json:"orders"`           // numberOrders summed over orders updates (not parsed)
	Pointers        map[string]int `json:"pointers,omitempty"`
	Other           map[string]int `json:"other,omitempty"` // other pduType2 / updateCode values
	Reactivations   int            `json:"reactivations"`
	// Frame and Pointer summarise the framebuffer and pointer state when
	// Options.Render is set.
	Frame   *bitmap.Stats        `json:"frame,omitempty"`
	Pointer *bitmap.PointerStats `json:"pointer,omitempty"`

	// Logon notifications (Save Session Info).
	Logon []wire.SaveSessionInfo `json:"logon,omitempty"`
	// Error Info received, if any (ERRINFO_* code).
	ErrorInfo  *uint32 `json:"error_info,omitempty"`
	Disconnect string  `json:"disconnect,omitempty"`
}

// maxReactivations bounds Deactivate All → Demand Active cycles.
const maxReactivations = 4

func pointerName(t uint16) string {
	switch t {
	case wire.PointerTypeSystem:
		return "system"
	case wire.PointerTypePosition:
		return "position"
	case wire.PointerTypeColor:
		return "color"
	case wire.PointerTypeCached:
		return "cached"
	case wire.PointerTypeNew:
		return "new"
	case wire.PointerTypeLarge:
		return "large"
	}
	return fmt.Sprintf("0x%04x", t)
}

func updateName(t uint16) string {
	switch t {
	case wire.UpdateTypeOrders:
		return "orders"
	case wire.UpdateTypeBitmap:
		return "bitmap"
	case wire.UpdateTypePalette:
		return "palette"
	case wire.UpdateTypeSynchronize:
		return "synchronize"
	}
	return fmt.Sprintf("0x%04x", t)
}

func bump(m *map[string]int, k string) {
	if *m == nil {
		*m = map[string]int{}
	}
	(*m)[k]++
}

// outputHandler applies decoded server output to the observation and, when
// rendering, to the framebuffer and pointer state.
type outputHandler struct {
	obs *Observation
	fb  *bitmap.Framebuffer
	ptr *bitmap.PointerState
}

func (h *outputHandler) palette() *[256]color.RGBA {
	if h.fb == nil {
		return nil
	}
	return h.fb.Palette()
}

func (h *outputHandler) update(u wire.Update) {
	bump(&h.obs.Updates, updateName(u.Type))
	h.obs.Orders += int(u.NumOrders)
	for _, b := range u.Bitmaps {
		h.obs.BitmapRects++
		h.obs.BitmapBytes += b.DataLength
		if b.Compressed {
			h.obs.Compressed++
		}
		if h.fb != nil {
			_ = h.fb.Draw(b) // failures are counted in fb.Summary().Errors
		}
	}
	if h.fb != nil && u.Type == wire.UpdateTypePalette {
		h.fb.SetPalette(u.Palette)
	}
}

func (h *outputHandler) pointer(p wire.Pointer) {
	bump(&h.obs.Pointers, pointerName(p.Type))
	if h.ptr != nil {
		_ = h.ptr.Apply(p, h.palette()) // failures are counted in ptr.Summary().Errors
	}
}

// fastPath handles one reassembled TS_FP_UPDATE.
func (h *outputHandler) fastPath(code uint8, data []byte) error {
	switch code {
	case wire.FastPathUpdateBitmap, wire.FastPathUpdatePalette:
		u, err := wire.DecodeUpdate(data)
		if err != nil {
			return err
		}
		h.update(u)
	case wire.FastPathUpdateSynchronize:
		bump(&h.obs.Updates, "synchronize")
	case wire.FastPathUpdateOrders:
		n, err := wire.FastPathOrdersCount(data)
		if err != nil {
			return err
		}
		bump(&h.obs.Updates, "orders")
		h.obs.Orders += int(n)
	default:
		if !wire.IsFastPathPointer(code) {
			bump(&h.obs.Other, "fp-"+wire.FastPathUpdateName(code))
			return nil
		}
		p, err := wire.DecodeFastPathPointer(code, data)
		if err != nil {
			return err
		}
		h.pointer(p)
	}
	return nil
}

// slowPath handles one Share Data PDU body after activation.
func (h *outputHandler) slowPath(d wire.DataPDU) error {
	switch d.Header.PDUType2 {
	case wire.PDUType2Update:
		u, err := wire.DecodeUpdate(d.Body)
		if err != nil {
			return err
		}
		h.update(u)
	case wire.PDUType2Pointer:
		p, err := wire.DecodePointer(d.Body)
		if err != nil {
			return err
		}
		h.pointer(p)
	case wire.PDUType2SaveSessionInfo:
		s, err := wire.DecodeSaveSessionInfo(d.Body)
		if err != nil {
			return err
		}
		h.obs.Logon = append(h.obs.Logon, s)
	default:
		bump(&h.obs.Other, fmt.Sprintf("0x%02x", d.Header.PDUType2))
	}
	return nil
}

// endObservation classifies a read error: a clean close or the window
// elapsing end the observation normally; anything else is an error.
func endObservation(obs *Observation, start time.Time, window time.Duration, err error) error {
	var disc *wire.DisconnectError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		obs.End = "closed"
		return nil
	case errors.As(err, &disc):
		obs.End, obs.Disconnect = "closed", disc.Error()
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() && time.Since(start) >= window {
		obs.End = "timeout"
		return nil
	}
	return fmt.Errorf("observe: %w", err)
}

// observe reads server PDUs for opts.Observe after activation: TPKT-framed
// Share Data PDUs on the I/O channel and fast-path update PDUs, told apart
// by their first byte (2.2.9.1.2). A Deactivate All is answered by re-running
// Capabilities Exchange and Connection Finalization. The read deadline is
// the shorter of the observation window and the context deadline already
// set on conn.
func observe(conn net.Conn, opts Options, res *Result) error {
	start := time.Now()
	obs := &Observation{End: "error"}
	res.Observation = obs
	h := &outputHandler{obs: obs}
	if opts.Render {
		w, hgt := desktopSize(opts)
		h.fb = bitmap.New(int(w), int(hgt))
		h.ptr = bitmap.NewPointerState(wire.DefaultPointerCacheSize)
		res.Framebuffer, res.Pointer = h.fb, h.ptr
	}
	defer func() {
		obs.Duration = time.Since(start)
		if h.fb != nil {
			s := h.fb.Summary()
			obs.Frame = &s
		}
		if h.ptr != nil {
			s := h.ptr.Summary()
			obs.Pointer = &s
		}
	}()
	bc, ok := conn.(*bufConn)
	if !ok {
		bc = newBufConn(conn)
	}
	if err := conn.SetReadDeadline(start.Add(opts.Observe)); err != nil {
		return err
	}
	var frag struct {
		active bool
		code   uint8
		data   []byte
	}
	for {
		first, err := bc.r.Peek(1)
		if err != nil {
			return endObservation(obs, start, opts.Observe, err)
		}
		if wire.IsFastPathHeader(first[0]) {
			_, _ = bc.r.ReadByte()
			fp, err := wire.ReadFastPathPDU(bc.r, first[0], 0)
			if err != nil {
				return endObservation(obs, start, opts.Observe, err)
			}
			obs.PDUs++
			obs.FastPathPDUs++
			for _, u := range fp.Updates {
				if u.Compressed {
					return fmt.Errorf("%w: bulk-compressed fast-path update (compression was not negotiated)", ErrUnexpectedPDU)
				}
				data := u.Data
				switch u.Fragmentation {
				case wire.FastPathFragmentFirst:
					frag.active, frag.code, frag.data = true, u.Code, append([]byte(nil), u.Data...)
					continue
				case wire.FastPathFragmentNext, wire.FastPathFragmentLast:
					if !frag.active || frag.code != u.Code {
						return fmt.Errorf("%w: fast-path fragment of update 0x%x without a first fragment", ErrUnexpectedPDU, u.Code)
					}
					frag.data = append(frag.data, u.Data...)
					if u.Fragmentation == wire.FastPathFragmentNext {
						continue
					}
					data, frag.active = frag.data, false
					obs.Fragments++
				}
				bump(&obs.FastPathUpdates, wire.FastPathUpdateName(u.Code))
				if err := h.fastPath(u.Code, data); err != nil {
					return fmt.Errorf("observe: %w", err)
				}
			}
			continue
		}

		data, err := readIO(bc, res)
		if err != nil {
			return endObservation(obs, start, opts.Observe, err)
		}
		obs.PDUs++
		ctl, _, err := wire.DecodeShareControl(data)
		if err != nil {
			return fmt.Errorf("observe: %w", err)
		}
		switch ctl.PDUType {
		case wire.PDUTypeDeactivateAll:
			if obs.Reactivations >= maxReactivations {
				return fmt.Errorf("%w: more than %d reactivations", ErrUnexpectedPDU, maxReactivations)
			}
			obs.Reactivations++
			demand, err := capabilityExchange(bc, opts, res)
			if err != nil {
				return fmt.Errorf("reactivation: %w", err)
			}
			if err := finalize(bc, demand, res); err != nil {
				return fmt.Errorf("reactivation: %w", err)
			}
			continue
		case wire.PDUTypeData:
		default:
			return fmt.Errorf("%w: share control pduType %d after activation", ErrUnexpectedPDU, ctl.PDUType)
		}
		d, err := wire.DecodeDataPDU(data)
		var ei *wire.ErrorInfo
		if errors.As(err, &ei) {
			code := ei.Code
			obs.ErrorInfo = &code
			continue
		}
		if err != nil {
			return fmt.Errorf("observe: %w", err)
		}
		if err := h.slowPath(d); err != nil {
			return fmt.Errorf("observe: %w", err)
		}
	}
}
