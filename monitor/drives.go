package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"rdp.local/kernel/wire"
)

const maxDriveFile = 64 << 20

// Paths are always device-root relative. Reject Windows namespaces, alternate
// streams, traversal and wildcards rather than cleaning them into other paths.
func drivePath(p string) (string, error) {
	if len(p) > 2048 || !utf8.ValidString(p) {
		return "", errors.New("invalid mapped path")
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "//") || strings.ContainsAny(p, ":*?\x00\r\n") {
		return "", errors.New("invalid mapped path")
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if p == "" || p == "/" {
		return "\\", nil
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || strings.ContainsAny(part, "<>\"|") {
			return "", errors.New("invalid mapped path")
		}
		for _, ch := range part {
			if ch < 32 {
				return "", errors.New("invalid mapped path")
			}
		}
	}
	return "\\" + strings.Join(parts, "\\"), nil
}

func (s *Session) driveIO(ctx context.Context, req []byte) (wire.IOCompletion, error) {
	if !s.m.cfg.AllowDriveControl || s.ctl.DriveRequest == nil {
		return wire.IOCompletion{}, ErrControl
	}
	select {
	case <-s.done:
		return wire.IOCompletion{}, errors.New("session ended")
	default:
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.ctl.DriveRequest(ctx, req)
}

func statusError(c wire.IOCompletion, err error) error {
	if err != nil {
		return err
	}
	if c.IoStatus != 0 {
		return fmt.Errorf("redirected drive status 0x%08X", c.IoStatus)
	}
	return nil
}
func (s *Session) openDrive(ctx context.Context, device uint32, path string, access, disposition, options uint32) (uint32, error) {
	s.audit.mu.Lock()
	d, ok := s.audit.devices[device]
	s.audit.mu.Unlock()
	if !ok || d.Type != wire.RDPDRDtypFilesystem || !d.Accepted {
		return 0, errors.New("mapped drive not available")
	}
	// OPEN_REPARSE_POINT: do not follow a final symlink/reparse point. Parent
	// traversal is still ultimately confined by the RDP client's mapping policy.
	c, err := s.driveIO(ctx, wire.EncodeCreate(device, 0, path, access, disposition, options|0x00200000))
	if err = statusError(c, err); err != nil {
		return 0, err
	}
	f, _, err := wire.ParseCreateResponse(c.Tail)
	return f, err
}
func (s *Session) closeDrive(device, file uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := s.driveIO(ctx, wire.EncodeClose(device, file, 0))
	return statusError(c, err)
}

func (s *Session) listDrive(ctx context.Context, device uint32, path string) (entries []wire.FileEntry, err error) {
	file, err := s.openDrive(ctx, device, path, wire.AccessListDir, wire.FileOpen, wire.OptionsDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if e := s.closeDrive(device, file); err == nil {
			err = e
		}
	}()
	entries = []wire.FileEntry{}
	for i := 0; i < 10000; i++ {
		pattern := ""
		if i == 0 {
			pattern = strings.TrimSuffix(path, "\\") + "\\*"
		}
		c, e := s.driveIO(ctx, wire.EncodeQueryDirectory(device, file, 0, wire.FileDirectoryInformation, i == 0, pattern))
		if e != nil {
			return nil, e
		}
		if c.IoStatus == wire.StatusNoMoreFiles || c.IoStatus == wire.StatusNoSuchFile {
			return entries, nil
		}
		if e = statusError(c, nil); e != nil {
			return nil, e
		}
		batch, e := wire.ParseDirectoryEntries(c.Tail, wire.FileDirectoryInformation)
		if e != nil {
			return nil, e
		}
		if len(c.Tail) >= 4 && c.Tail[0] == 0 && c.Tail[1] == 0 && c.Tail[2] == 0 && c.Tail[3] == 0 {
			return entries, nil
		}
		entries = append(entries, batch...)
		if len(entries) > 10000 {
			break
		}
	}
	return nil, errors.New("directory exceeds 10000 entries or responses; narrow the path")
}

// Reject reported reparse points in every component before file operations.
// This is not a replacement for a client enforcing its own mapped root.
func (s *Session) checkDrivePath(ctx context.Context, device uint32, path string, create bool) error {
	if path == "\\" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "\\"), "\\")
	parent := "\\"
	for i, part := range parts {
		entries, err := s.listDrive(ctx, device, parent)
		if err != nil {
			return err
		}
		found := false
		for _, f := range entries {
			if !strings.EqualFold(f.Name, part) {
				continue
			}
			found = true
			if f.Attributes&0x400 != 0 {
				return errors.New("symbolic links/reparse points are not allowed")
			}
			if i < len(parts)-1 && !f.IsDir {
				return errors.New("parent is not a directory")
			}
			if create && i == len(parts)-1 {
				return errors.New("file already exists; overwriting is disabled")
			}
			break
		}
		if !found && !(create && i == len(parts)-1) {
			return errors.New("mapped path not found")
		}
		parent = strings.TrimSuffix(parent, "\\") + "\\" + part
	}
	return nil
}

func (s *Session) readDrive(ctx context.Context, device uint32, path string, dst io.Writer) (total uint64, err error) {
	file, err := s.openDrive(ctx, device, path, wire.AccessReadFile, wire.FileOpen, wire.OptionsFile)
	if err != nil {
		return 0, err
	}
	defer func() {
		if e := s.closeDrive(device, file); err == nil {
			err = e
		}
	}()
	for {
		c, e := s.driveIO(ctx, wire.EncodeRead(device, file, 0, 64<<10, total))
		if e != nil {
			return total, e
		}
		if c.IoStatus == 0xC0000011 {
			return total, nil
		} // STATUS_END_OF_FILE
		if e = statusError(c, nil); e != nil {
			return total, e
		}
		data, e := wire.ParseReadResponse(c.Tail)
		if e != nil {
			return total, e
		}
		if len(data) > 64<<10 {
			return total, wire.ErrRDPDR
		}
		if len(data) == 0 {
			return total, nil
		}
		if total+uint64(len(data)) > maxDriveFile {
			return total, errors.New("file exceeds 64 MiB download limit")
		}
		n, e := dst.Write(data)
		total += uint64(n)
		if e != nil {
			return total, e
		}
		if n != len(data) {
			return total, io.ErrShortWrite
		}
	}
}

func (s *Session) writeDrive(ctx context.Context, device uint32, path string, src io.Reader) (total uint64, err error) {
	file, err := s.openDrive(ctx, device, path, wire.AccessWriteNew, wire.FileCreate, wire.OptionsFile)
	if err != nil {
		return 0, err
	}
	defer func() {
		if e := s.closeDrive(device, file); err == nil {
			err = e
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, e := src.Read(buf)
		if n > 0 {
			if total+uint64(n) > maxDriveFile {
				return total, errors.New("file exceeds 64 MiB upload limit")
			}
			for off := 0; off < n; {
				c, err := s.driveIO(ctx, wire.EncodeWrite(device, file, 0, total, buf[off:n]))
				if err = statusError(c, err); err != nil {
					return total, err
				}
				wrote, err := wire.ParseWriteResponse(c.Tail)
				if err != nil {
					return total, err
				}
				if wrote == 0 || wrote > uint32(n-off) {
					return total, io.ErrShortWrite
				}
				off += int(wrote)
				total += uint64(wrote)
			}
		}
		if e == io.EOF {
			return total, nil
		}
		if e != nil {
			return total, e
		}
	}
}

func (s *Session) deleteDrive(ctx context.Context, device uint32, path string) (err error) {
	// Non-directory opens intentionally prohibit recursive deletion.
	file, err := s.openDrive(ctx, device, path, wire.AccessDelete, wire.FileOpen, wire.OptionsFile)
	if err != nil {
		return err
	}
	defer func() {
		if e := s.closeDrive(device, file); err == nil {
			err = e
		}
	}()
	c, err := s.driveIO(ctx, wire.EncodeSetDisposition(device, file, 0))
	return statusError(c, err)
}
