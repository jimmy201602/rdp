package wire

import (
	"encoding/binary"
	"fmt"
)

// Typed capability sets (MS-RDPBCGR 2.2.7). The client advertises a small,
// conservative set: no bulk compression, fast-path output but no fast-path
// input, no orders beyond what is mandatory to declare, no bitmap caching.
// Values follow the field tables of the specification; the Confirm Active
// sample in 4.1.13 was used to check the layouts.

const (
	OSMajorTypeUnspecified uint16 = 0x0000
	OSMajorTypeWindows     uint16 = 0x0001
	OSMajorTypeUnix        uint16 = 0x0004
	OSMajorTypeOSX         uint16 = 0x0006
	OSMinorTypeUnspecified uint16 = 0x0000
	OSMinorTypeWindowsNT   uint16 = 0x0003
	OSMinorTypeNativeX     uint16 = 0x0007

	capsProtocolVersion uint16 = 0x0200

	GeneralFastPathOutputSupported  uint16 = 0x0001
	GeneralLongCredentialsSupported uint16 = 0x0004
	GeneralAutoReconnectSupported   uint16 = 0x0008
	GeneralEncSaltedChecksum        uint16 = 0x0010
	GeneralNoBitmapCompressionHdr   uint16 = 0x0400

	OrderNegotiateOrderSupport   uint16 = 0x0002
	OrderZeroBoundsDeltasSupport uint16 = 0x0008
	OrderColorIndexSupport       uint16 = 0x0020
	OrderSolidPatternBrushOnly   uint16 = 0x0040
	OrderFlagsExtraFlags         uint16 = 0x0080

	// orderSupportExFlags (TS_ORDER_CAPABILITYSET), valid with OrderFlagsExtraFlags.
	OrderSupportExCacheBitmapV3     uint16 = 0x0002
	OrderSupportExAltSecFrameMarker uint16 = 0x0004

	// drawingFlags (TS_BITMAP_CAPABILITYSET).
	DrawAllowDynamicColorFidelity uint8 = 0x02
	DrawAllowColorSubsampling     uint8 = 0x04
	DrawAllowSkipAlpha            uint8 = 0x08

	InputFlagScancodes      uint16 = 0x0001
	InputFlagMouseX         uint16 = 0x0004
	InputFlagFastPathInput  uint16 = 0x0008
	InputFlagUnicode        uint16 = 0x0010
	InputFlagFastPathInput2 uint16 = 0x0020
	InputFlagMouseHWheel    uint16 = 0x0100

	controlPriorityNever uint16 = 0x0002
	soundFlagBeeps       uint16 = 0x0001
	fontSupportFontList  uint16 = 0x0001
	brushDefault         uint32 = 0x0000
	glyphSupportNone     uint16 = 0x0000
	vcCapsNoCompr        uint32 = 0x0000
)

// GeneralCapability is TS_GENERAL_CAPABILITYSET (2.2.7.1.1).
type GeneralCapability struct {
	OSMajorType           uint16
	OSMinorType           uint16
	ProtocolVersion       uint16
	CompressionTypes      uint16
	ExtraFlags            uint16
	UpdateCapabilityFlag  uint16
	RemoteUnshareFlag     uint16
	CompressionLevel      uint16
	RefreshRectSupport    uint8
	SuppressOutputSupport uint8
}

func (g GeneralCapability) Set() CapabilitySet {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint16(b, g.OSMajorType)
	binary.LittleEndian.PutUint16(b[2:], g.OSMinorType)
	binary.LittleEndian.PutUint16(b[4:], capsProtocolVersion)
	binary.LittleEndian.PutUint16(b[8:], g.CompressionTypes)
	binary.LittleEndian.PutUint16(b[10:], g.ExtraFlags)
	binary.LittleEndian.PutUint16(b[12:], g.UpdateCapabilityFlag)
	binary.LittleEndian.PutUint16(b[14:], g.RemoteUnshareFlag)
	binary.LittleEndian.PutUint16(b[16:], g.CompressionLevel)
	b[18] = g.RefreshRectSupport
	b[19] = g.SuppressOutputSupport
	return CapabilitySet{Type: CapsTypeGeneral, Data: b}
}

// DecodeGeneralCapability parses a general capability set. Servers may send
// the pre-5.1 form without the two trailing bytes.
func DecodeGeneralCapability(s CapabilitySet) (GeneralCapability, error) {
	var g GeneralCapability
	if s.Type != CapsTypeGeneral || len(s.Data) < 18 {
		return g, fmt.Errorf("%w: general capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	d := s.Data
	g.OSMajorType = binary.LittleEndian.Uint16(d)
	g.OSMinorType = binary.LittleEndian.Uint16(d[2:])
	g.ProtocolVersion = binary.LittleEndian.Uint16(d[4:])
	g.CompressionTypes = binary.LittleEndian.Uint16(d[8:])
	g.ExtraFlags = binary.LittleEndian.Uint16(d[10:])
	g.UpdateCapabilityFlag = binary.LittleEndian.Uint16(d[12:])
	g.RemoteUnshareFlag = binary.LittleEndian.Uint16(d[14:])
	g.CompressionLevel = binary.LittleEndian.Uint16(d[16:])
	if len(d) >= 20 {
		g.RefreshRectSupport = d[18]
		g.SuppressOutputSupport = d[19]
	}
	return g, nil
}

// BitmapCapability is TS_BITMAP_CAPABILITYSET (2.2.7.1.2).
type BitmapCapability struct {
	PreferredBitsPerPixel    uint16
	DesktopWidth             uint16
	DesktopHeight            uint16
	DesktopResizeFlag        uint16
	DrawingFlags             uint8
	MultipleRectangleSupport uint16
}

func (b BitmapCapability) Set() CapabilitySet {
	d := make([]byte, 24)
	binary.LittleEndian.PutUint16(d, b.PreferredBitsPerPixel)
	binary.LittleEndian.PutUint16(d[2:], 1) // receive1BitPerPixel
	binary.LittleEndian.PutUint16(d[4:], 1) // receive4BitsPerPixel
	binary.LittleEndian.PutUint16(d[6:], 1) // receive8BitsPerPixel
	binary.LittleEndian.PutUint16(d[8:], b.DesktopWidth)
	binary.LittleEndian.PutUint16(d[10:], b.DesktopHeight)
	binary.LittleEndian.PutUint16(d[14:], b.DesktopResizeFlag)
	binary.LittleEndian.PutUint16(d[16:], 1) // bitmapCompressionFlag MUST be TRUE
	d[18] = 0                                // highColorFlags
	d[19] = b.DrawingFlags
	binary.LittleEndian.PutUint16(d[20:], b.MultipleRectangleSupport)
	return CapabilitySet{Type: CapsTypeBitmap, Data: d}
}

func DecodeBitmapCapability(s CapabilitySet) (BitmapCapability, error) {
	var b BitmapCapability
	if s.Type != CapsTypeBitmap || len(s.Data) < 24 {
		return b, fmt.Errorf("%w: bitmap capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	d := s.Data
	b.PreferredBitsPerPixel = binary.LittleEndian.Uint16(d)
	b.DesktopWidth = binary.LittleEndian.Uint16(d[8:])
	b.DesktopHeight = binary.LittleEndian.Uint16(d[10:])
	b.DesktopResizeFlag = binary.LittleEndian.Uint16(d[14:])
	b.DrawingFlags = d[19]
	b.MultipleRectangleSupport = binary.LittleEndian.Uint16(d[20:])
	return b, nil
}

// OrderCapability is TS_ORDER_CAPABILITYSET (2.2.7.1.3). OrderSupport holds
// the 32 TS_NEG_*_INDEX flags.
type OrderCapability struct {
	OrderFlags          uint16
	OrderSupport        [32]byte
	TextFlags           uint16
	OrderSupportExFlags uint16
	DesktopSaveSize     uint32
	TextANSICodePage    uint16
}

func (o OrderCapability) Set() CapabilitySet {
	d := make([]byte, 84)
	// terminalDescriptor[16] and pad4octetsA stay zero.
	binary.LittleEndian.PutUint16(d[20:], 1)  // desktopSaveXGranularity
	binary.LittleEndian.PutUint16(d[22:], 20) // desktopSaveYGranularity
	binary.LittleEndian.PutUint16(d[26:], 1)  // maximumOrderLevel = ORD_LEVEL_1_ORDERS
	binary.LittleEndian.PutUint16(d[28:], 0)  // numberFonts
	binary.LittleEndian.PutUint16(d[30:], o.OrderFlags)
	copy(d[32:64], o.OrderSupport[:])
	binary.LittleEndian.PutUint16(d[64:], o.TextFlags)
	binary.LittleEndian.PutUint16(d[66:], o.OrderSupportExFlags)
	binary.LittleEndian.PutUint32(d[72:], o.DesktopSaveSize)
	binary.LittleEndian.PutUint16(d[80:], o.TextANSICodePage)
	return CapabilitySet{Type: CapsTypeOrder, Data: d}
}

func DecodeOrderCapability(s CapabilitySet) (OrderCapability, error) {
	var o OrderCapability
	if s.Type != CapsTypeOrder || len(s.Data) < 84 {
		return o, fmt.Errorf("%w: order capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	d := s.Data
	o.OrderFlags = binary.LittleEndian.Uint16(d[30:])
	copy(o.OrderSupport[:], d[32:64])
	o.TextFlags = binary.LittleEndian.Uint16(d[64:])
	o.OrderSupportExFlags = binary.LittleEndian.Uint16(d[66:])
	o.DesktopSaveSize = binary.LittleEndian.Uint32(d[72:])
	o.TextANSICodePage = binary.LittleEndian.Uint16(d[80:])
	return o, nil
}

// InputCapability is TS_INPUT_CAPABILITYSET (2.2.7.1.6).
type InputCapability struct {
	InputFlags          uint16
	KeyboardLayout      uint32
	KeyboardType        uint32
	KeyboardSubType     uint32
	KeyboardFunctionKey uint32
}

func (i InputCapability) Set() CapabilitySet {
	d := make([]byte, 84)
	binary.LittleEndian.PutUint16(d, i.InputFlags)
	binary.LittleEndian.PutUint32(d[4:], i.KeyboardLayout)
	binary.LittleEndian.PutUint32(d[8:], i.KeyboardType)
	binary.LittleEndian.PutUint32(d[12:], i.KeyboardSubType)
	binary.LittleEndian.PutUint32(d[16:], i.KeyboardFunctionKey)
	// imeFileName[64] stays zero.
	return CapabilitySet{Type: CapsTypeInput, Data: d}
}

func DecodeInputCapability(s CapabilitySet) (InputCapability, error) {
	var i InputCapability
	if s.Type != CapsTypeInput || len(s.Data) < 4 {
		return i, fmt.Errorf("%w: input capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	i.InputFlags = binary.LittleEndian.Uint16(s.Data)
	if len(s.Data) >= 20 {
		i.KeyboardLayout = binary.LittleEndian.Uint32(s.Data[4:])
		i.KeyboardType = binary.LittleEndian.Uint32(s.Data[8:])
		i.KeyboardSubType = binary.LittleEndian.Uint32(s.Data[12:])
		i.KeyboardFunctionKey = binary.LittleEndian.Uint32(s.Data[16:])
	}
	return i, nil
}

// ShareCapability is TS_SHARE_CAPABILITYSET (2.2.7.2.4). Clients send 0; the
// server reports its MCS channel id.
type ShareCapability struct{ NodeID uint16 }

func (s ShareCapability) Set() CapabilitySet {
	d := make([]byte, 4)
	binary.LittleEndian.PutUint16(d, s.NodeID)
	return CapabilitySet{Type: CapsTypeShare, Data: d}
}

func DecodeShareCapability(s CapabilitySet) (ShareCapability, error) {
	if s.Type != CapsTypeShare || len(s.Data) < 2 {
		return ShareCapability{}, fmt.Errorf("%w: share capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	return ShareCapability{NodeID: binary.LittleEndian.Uint16(s.Data)}, nil
}

// DefaultPointerCacheSize is the colorPointerCacheSize / pointerCacheSize
// advertised by DefaultClientCapabilities.
const DefaultPointerCacheSize = 20

// PointerCapability is TS_POINTER_CAPABILITYSET (2.2.7.1.5).
type PointerCapability struct {
	ColorPointerFlag      uint16
	ColorPointerCacheSize uint16
	PointerCacheSize      uint16
}

func (p PointerCapability) Set() CapabilitySet {
	d := make([]byte, 6)
	binary.LittleEndian.PutUint16(d, p.ColorPointerFlag)
	binary.LittleEndian.PutUint16(d[2:], p.ColorPointerCacheSize)
	binary.LittleEndian.PutUint16(d[4:], p.PointerCacheSize)
	return CapabilitySet{Type: CapsTypePointer, Data: d}
}

// DecodePointerCapability parses a pointer capability set. The pre-5.0 form
// omits pointerCacheSize; it then defaults to colorPointerCacheSize.
func DecodePointerCapability(s CapabilitySet) (PointerCapability, error) {
	var p PointerCapability
	if s.Type != CapsTypePointer || len(s.Data) < 4 {
		return p, fmt.Errorf("%w: pointer capability set type 0x%04x, %d bytes", ErrShare, s.Type, len(s.Data))
	}
	p.ColorPointerFlag = binary.LittleEndian.Uint16(s.Data)
	p.ColorPointerCacheSize = binary.LittleEndian.Uint16(s.Data[2:])
	p.PointerCacheSize = p.ColorPointerCacheSize
	if len(s.Data) >= 6 {
		p.PointerCacheSize = binary.LittleEndian.Uint16(s.Data[4:])
	}
	return p, nil
}

func u16Set(typ uint16, values ...uint16) CapabilitySet {
	d := make([]byte, 2*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint16(d[2*i:], v)
	}
	return CapabilitySet{Type: typ, Data: d}
}

func u32Set(typ uint16, values ...uint32) CapabilitySet {
	d := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(d[4*i:], v)
	}
	return CapabilitySet{Type: typ, Data: d}
}

// ControlCapabilitySet is TS_CONTROL_CAPABILITYSET (2.2.7.2.2) with the
// values every client sends: no control flags, never interested in control.
func ControlCapabilitySet() CapabilitySet {
	return u16Set(CapsTypeControl, 0, 0, controlPriorityNever, controlPriorityNever)
}

// ActivationCapabilitySet is TS_WINDOWACTIVATION_CAPABILITYSET (2.2.7.2.3), all zero.
func ActivationCapabilitySet() CapabilitySet { return u16Set(CapsTypeActivation, 0, 0, 0, 0) }

// FontCapabilitySet is TS_FONT_CAPABILITYSET (2.2.7.2.5).
func FontCapabilitySet() CapabilitySet { return u16Set(CapsTypeFont, fontSupportFontList, 0) }

// SoundCapabilitySet is TS_SOUND_CAPABILITYSET (2.2.7.1.11).
func SoundCapabilitySet() CapabilitySet { return u16Set(CapsTypeSound, soundFlagBeeps, 0) }

// ColorCacheCapabilitySet is TS_COLORCACHE_CAPABILITYSET (MS-RDPEGDI 2.2.1.1)
// with the usual six colour tables.
func ColorCacheCapabilitySet() CapabilitySet { return u16Set(CapsTypeColorCache, 6, 0) }

// BrushCapabilitySet is TS_BRUSH_CAPABILITYSET (2.2.7.1.7).
func BrushCapabilitySet() CapabilitySet { return u32Set(CapsTypeBrush, brushDefault) }

// VirtualChannelCapabilitySet is TS_VIRTUALCHANNEL_CAPABILITYSET (2.2.7.1.10)
// without compression and with the default 1600-byte chunk size.
func VirtualChannelCapabilitySet() CapabilitySet {
	return u32Set(CapsTypeVirtualChannel, vcCapsNoCompr, 1600)
}

// OffscreenCacheCapabilitySet is TS_OFFSCREEN_CAPABILITYSET (2.2.7.1.9), disabled.
func OffscreenCacheCapabilitySet() CapabilitySet {
	return CapabilitySet{Type: CapsTypeOffscreenCache, Data: make([]byte, 8)}
}

// GlyphCacheCapabilitySet is TS_GLYPHCACHE_CAPABILITYSET (2.2.7.1.8) with
// GLYPH_SUPPORT_NONE; cache definitions are left zero.
func GlyphCacheCapabilitySet() CapabilitySet {
	d := make([]byte, 48)
	binary.LittleEndian.PutUint16(d[44:], glyphSupportNone)
	return CapabilitySet{Type: CapsTypeGlyphCache, Data: d}
}

// BitmapCacheCapabilitySet is the revision 1 TS_BITMAPCACHE_CAPABILITYSET
// (2.2.7.1.4.1): 24 pad bytes and three empty cache definitions.
func BitmapCacheCapabilitySet() CapabilitySet {
	return CapabilitySet{Type: CapsTypeBitmapCache, Data: make([]byte, 36)}
}

// ClientCapabilityOptions parameterises DefaultClientCapabilities.
type ClientCapabilityOptions struct {
	DesktopWidth   uint16
	DesktopHeight  uint16
	ColorDepth     uint16
	KeyboardLayout uint32
	KeyboardType   uint32
	FunctionKeys   uint32
}

// DefaultClientCapabilities returns the conservative capability sets this
// client sends in Confirm Active.
func DefaultClientCapabilities(o ClientCapabilityOptions) []CapabilitySet {
	var orders OrderCapability
	orders.OrderFlags = OrderNegotiateOrderSupport | OrderZeroBoundsDeltasSupport
	orders.TextANSICodePage = 1252
	return []CapabilitySet{
		GeneralCapability{
			OSMajorType: OSMajorTypeUnix,
			OSMinorType: OSMinorTypeUnspecified,
			ExtraFlags:  GeneralLongCredentialsSupported | GeneralNoBitmapCompressionHdr | GeneralFastPathOutputSupported | GeneralAutoReconnectSupported,
		}.Set(),
		BitmapCapability{
			PreferredBitsPerPixel:    o.ColorDepth,
			DesktopWidth:             o.DesktopWidth,
			DesktopHeight:            o.DesktopHeight,
			DesktopResizeFlag:        1,
			MultipleRectangleSupport: 1,
		}.Set(),
		orders.Set(),
		BitmapCacheCapabilitySet(),
		ColorCacheCapabilitySet(),
		ActivationCapabilitySet(),
		ControlCapabilitySet(),
		PointerCapability{ColorPointerFlag: 1, ColorPointerCacheSize: DefaultPointerCacheSize, PointerCacheSize: DefaultPointerCacheSize}.Set(),
		ShareCapability{}.Set(),
		InputCapability{
			InputFlags:          InputFlagScancodes | InputFlagUnicode | InputFlagMouseX | InputFlagMouseHWheel,
			KeyboardLayout:      o.KeyboardLayout,
			KeyboardType:        o.KeyboardType,
			KeyboardFunctionKey: o.FunctionKeys,
		}.Set(),
		SoundCapabilitySet(),
		FontCapabilitySet(),
		BrushCapabilitySet(),
		GlyphCacheCapabilitySet(),
		OffscreenCacheCapabilitySet(),
		VirtualChannelCapabilitySet(),
	}
}
