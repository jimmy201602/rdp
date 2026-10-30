package monitor

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rdp.local/kernel/wire"
)

// Event deliberately contains no key codes, typed text, clipboard body or file
// contents. RDP input cannot tell us whether a field is a password field.
type Event struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Action string `json:"action"`
	Device uint32 `json:"device,omitempty"`
	Path   string `json:"path,omitempty"`
	Bytes  uint64 `json:"bytes,omitempty"`
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
	X      uint16 `json:"x,omitempty"`
	Y      uint16 `json:"y,omitempty"`
}

type Device struct {
	ID       uint32 `json:"id"`
	Type     uint32 `json:"type"`
	Name     string `json:"name"`
	Accepted bool   `json:"accepted"`
}

type fileKey struct{ device, file uint32 }
type auditState struct {
	mu         sync.Mutex
	devices    map[uint32]Device
	requests   map[uint32]wire.IORequest
	files      map[fileKey]string
	formats    [2]map[uint32]string
	longNames  [2]bool
	requested  [2]uint32
	hasRequest [2]bool
	lastMove   map[string]time.Time
	queue      chan Event
	dropped    atomic.Uint64
	operations chan struct{}
}

func newAudit() *auditState {
	return &auditState{devices: map[uint32]Device{}, requests: map[uint32]wire.IORequest{}, files: map[fileKey]string{}, lastMove: map[string]time.Time{}, queue: make(chan Event, 2048), operations: make(chan struct{}, 1)}
}

func (s *Session) emit(e Event) {
	if len(e.Path) > 4096 {
		e.Path = e.Path[:4096]
	}
	if len(e.Detail) > 1024 {
		e.Detail = e.Detail[:1024]
	}
	select {
	case s.audit.queue <- e:
	default:
		s.audit.dropped.Add(1)
	}
}

func (s *Session) flushEvents() {
	// Only the recorder loop writes records. Timestamp at dequeue keeps frame
	// and event record times monotonic, including the final drain on disconnect.
	for i := 0; i < 2048; i++ {
		select {
		case e := <-s.audit.queue:
			js, _ := json.Marshal(e)
			rec := encodeRecord(RecEvent, s.ms(), js)
			s.broadcast(rec)
			s.record(rec)
		default:
			i = 2048
		}
	}
	if n := s.audit.dropped.Swap(0); n != 0 {
		js, _ := json.Marshal(Event{Kind: "system", Source: "gateway", Action: "events_dropped", Detail: fmt.Sprintf("队列已满，丢弃 %d 条事件", n)})
		rec := encodeRecord(RecEvent, s.ms(), js)
		s.broadcast(rec)
		s.record(rec)
	}
}

func (s *Session) inputEvents(events []wire.InputEvent, source string) {
	a := s.audit
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range events {
		ev := Event{Source: source}
		switch e.Kind {
		case wire.InputKindScancode, wire.InputKindUnicode:
			ev.Kind, ev.Action, ev.Detail = "keyboard", "input", "按键事件（内容已隐藏）"
		case wire.InputKindMouse, wire.InputKindMouseX:
			ev.Kind, ev.X, ev.Y = "mouse", e.X, e.Y
			switch {
			case e.Flags&0x0600 != 0:
				ev.Action = "wheel"
			case e.Flags&0x7000 != 0 || e.Kind == wire.InputKindMouseX:
				ev.Action = "button_up"
				if e.Flags&0x8000 != 0 {
					ev.Action = "button_down"
				}
			default:
				if time.Since(a.lastMove[source]) < 200*time.Millisecond {
					continue
				}
				a.lastMove[source] = time.Now()
				ev.Action = "move"
			}
		default:
			continue
		}
		s.emit(ev)
	}
}

func (s *Session) Devices() []Device {
	a := s.audit
	a.mu.Lock()
	out := make([]Device, 0, len(a.devices)+1)
	for _, d := range a.devices {
		out = append(out, d)
	}
	a.mu.Unlock()
	if d, ok := s.webDevice(); ok {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Session) ClientChannel(name string, data []byte) { s.channel(true, name, data) }
func (s *Session) ServerChannel(name string, data []byte) { s.channel(false, name, data) }
func (s *Session) channel(client bool, name string, data []byte) {
	a := s.audit
	a.mu.Lock()
	defer a.mu.Unlock()
	if name == "cliprdr" {
		s.clipboard(client, data)
		return
	}
	if name != "rdpdr" {
		return
	}
	h, b, err := wire.DecodeRDPDRHeader(data)
	if err != nil || h.Component != wire.RDPDRCtypCore {
		return
	}
	switch h.PacketID {
	case wire.PakidCoreDevicelistAnnounce:
		if !client {
			return
		}
		ds, err := wire.DecodeDeviceAnnounce(b)
		if err != nil {
			return
		}
		for _, d := range ds {
			if len(a.devices) >= 256 {
				break
			}
			name := d.Label
			if name == "" {
				name = d.DosName
			}
			a.devices[d.ID] = Device{ID: d.ID, Type: d.Type, Name: name}
			s.emit(Event{Kind: "device", Source: "client", Action: "announce", Device: d.ID, Detail: name})
		}
	case wire.PakidCoreDeviceReply:
		if client || len(b) < 8 {
			return
		}
		id, status := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
		if d, ok := a.devices[id]; ok {
			d.Accepted = status == 0
			a.devices[id] = d
		}
	case wire.PakidCoreDevicelistRemove:
		if !client {
			return
		}
		ids, err := wire.DecodeDevicelistRemove(b)
		if err != nil {
			return
		}
		for _, id := range ids {
			delete(a.devices, id)
			for k := range a.files {
				if k.device == id {
					delete(a.files, k)
				}
			}
			for k, r := range a.requests {
				if r.DeviceID == id {
					delete(a.requests, k)
				}
			}
			s.emit(Event{Kind: "device", Source: "client", Action: "remove", Device: id})
		}
	case wire.PakidCoreDeviceIORequest:
		if client {
			return
		}
		req, err := wire.DecodeIORequest(b)
		if err != nil || len(a.requests) >= 4096 {
			return
		}
		if d, ok := a.devices[req.DeviceID]; !ok || d.Type != wire.RDPDRDtypFilesystem {
			return
		}
		if req.Path == "" {
			req.Path = a.files[fileKey{req.DeviceID, req.FileID}]
		}
		a.requests[req.CompletionID] = req
	case wire.PakidCoreDeviceIOCompletion:
		if !client {
			return
		}
		c, err := wire.DecodeIOCompletion(b)
		if err != nil {
			return
		}
		req, ok := a.requests[c.CompletionID]
		if !ok || req.DeviceID != c.DeviceID {
			return
		}
		delete(a.requests, c.CompletionID)
		ev := Event{Kind: "file", Source: "target", Device: c.DeviceID, Path: req.Path, Status: fmt.Sprintf("0x%08X", c.IoStatus)}
		switch req.Major {
		case wire.IRPMJCreate:
			ev.Action = "open"
			if c.IoStatus == 0 {
				if id, _, err := wire.ParseCreateResponse(c.Tail); err == nil && len(a.files) < 4096 {
					a.files[fileKey{c.DeviceID, id}] = req.Path
				}
			}
		case wire.IRPMJClose:
			ev.Action = "close"
			delete(a.files, fileKey{c.DeviceID, req.FileID})
		case wire.IRPMJRead:
			ev.Action = "read_upload"
			if c.IoStatus == 0 {
				if data, err := wire.ParseReadResponse(c.Tail); err == nil {
					ev.Bytes = uint64(len(data))
				}
			}
		case wire.IRPMJWrite:
			ev.Action = "write_download"
			if c.IoStatus == 0 {
				if n, err := wire.ParseWriteResponse(c.Tail); err == nil {
					ev.Bytes = uint64(n)
				}
			}
		case wire.IRPMJSetInformation:
			ev.Action = "set_info"
			if req.FsInformationClass == 13 {
				ev.Action = "delete"
			}
			if req.FsInformationClass == 10 {
				ev.Action = "rename"
			}
		default:
			return
		}
		s.emit(ev)
	}
}

func (s *Session) clipboard(client bool, p []byte) {
	a := s.audit
	side := 0
	source := "target"
	if client {
		side = 1
		source = "client"
	}
	h, b, err := wire.DecodeClipHeader(p)
	if err != nil {
		return
	}
	ev := Event{Kind: "clipboard", Source: source}
	switch h.MsgType {
	case wire.CBClipCaps:
		if len(b) < 4 {
			return
		}
		n := int(binary.LittleEndian.Uint16(b))
		b = b[4:]
		for i := 0; i < n && len(b) >= 4; i++ {
			typ, length := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
			if length < 4 || length > len(b) {
				break
			}
			if typ == 1 && length >= 12 {
				a.longNames[side] = binary.LittleEndian.Uint32(b[8:])&2 != 0
			}
			b = b[length:]
		}
		return
	case wire.CBFormatList:
		formats := wire.DecodeFormatList(b, a.longNames[0] && a.longNames[1])
		a.formats[side] = map[uint32]string{}
		var names []string
		for _, f := range formats {
			if len(names) >= 64 {
				break
			}
			name := f.Name
			if name == "" {
				name = fmt.Sprintf("format-%d", f.ID)
			}
			a.formats[side][f.ID] = name
			names = append(names, name)
		}
		ev.Action = "formats"
		ev.Detail = strings.Join(names, ", ")
	case wire.CBFormatDataRequest:
		id, err := wire.DecodeFormatDataRequest(b)
		if err != nil {
			return
		}
		a.requested[1-side], a.hasRequest[1-side] = id, true
		return
	case wire.CBFormatDataResponse:
		ev.Action = "data"
		ev.Bytes = uint64(len(b))
		ev.Detail = "正文不记录"
		if h.MsgFlags&wire.CBResponseFail != 0 {
			ev.Status = "failed"
		} else {
			ev.Status = "ok"
		}
		if a.hasRequest[side] {
			name := a.formats[side][a.requested[side]]
			if name == "FileGroupDescriptorW" && h.MsgFlags&wire.CBResponseOK != 0 {
				if files, err := wire.DecodeFileList(b); err == nil {
					var names []string
					for _, f := range files {
						if len(names) >= 32 {
							break
						}
						names = append(names, fmt.Sprintf("%s (%d B)", f.Name, f.Size))
					}
					ev.Detail = strings.Join(names, ", ")
				}
			}
			a.hasRequest[side] = false
		}
	case wire.CBFilecontentsResponse:
		ev.Action = "file_data"
		if len(b) >= 4 {
			ev.Bytes = uint64(len(b) - 4)
		}
		ev.Status = "ok"
		if h.MsgFlags&wire.CBResponseFail != 0 {
			ev.Status = "failed"
		}
	default:
		return
	}
	s.emit(ev)
}
