package tasklist

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// The fixtures follow the layouts of spec S37 section 3 (L1 to L9).
type blob struct {
	b    []byte
	base int
}

func (w *blob) record()       { w.base = len(w.b) }
func (w *blob) raw(p ...byte) { w.b = append(w.b, p...) }
func (w *blob) le16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *blob) le32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *blob) le64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }

func (w *blob) pad() {
	for (len(w.b)-w.base)%slot != 0 {
		w.b = append(w.b, 0x48)
	}
}

func (w *blob) slotByte(v byte)  { w.raw(v); w.pad() }
func (w *blob) slotU16(v uint16) { w.le16(v); w.pad() }
func (w *blob) slotU32(v uint32) { w.le32(v); w.pad() }

func (w *blob) slotted(p []byte) {
	w.slotU32(uint32(len(p)))
	w.raw(p...)
	w.pad()
}

func (w *blob) packed(p []byte) {
	w.le32(uint32(len(p)))
	w.raw(p...)
	w.pad()
}

func (w *blob) boundary(local byte, ft uint64) {
	w.raw(local, 0x07, 0x05, 0, 0, 0, 0x18, 0)
	w.le64(ft)
}

func utf16z(s string) []byte { return append(utf16le(s), 0, 0) }

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func filetime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10_000_000 + uint64(t.Nanosecond()/100)
}

// S-1-5-18 and S-1-5-21-1-2-3-1001 in wire form.
var (
	sidSystem = []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	sidUser   = []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0}
)

func (w *blob) account(sid []byte, name string) {
	if sid == nil {
		w.slotByte(1)
		return
	}
	w.slotByte(0)
	w.slotByte(0)
	w.slotU32(5)
	w.slotted(sid)
	if name == "" {
		w.slotted(nil)
	} else {
		w.slotted(utf16z(name))
	}
}

type headerSpec struct {
	format   uint32
	flags    uint32
	id       string
	sid      []byte
	user     string
	settings []byte
}

func (w *blob) header(h headerSpec) {
	w.record()
	w.slotU32(h.format)
	w.boundary(0, 0)
	w.boundary(0, ^uint64(0))
	w.slotU32(h.flags)
	w.slotU32(0x2D152FCD)
	w.slotted(utf16z(h.id))
	w.slotted(nil)
	w.account(h.sid, h.user)
	w.slotted(h.settings)
}

func settingsBlock(limit, priority, restartInterval, restartCount uint32, long bool) []byte {
	var w blob
	for _, v := range []uint32{600, 3600, limit, unsetSeconds, priority, restartInterval, restartCount} {
		w.le32(v)
	}
	w.raw(make([]byte, 16)...)
	if long {
		w.raw(make([]byte, settingsLong-settingsShort)...)
	}
	return w.b
}

type timedSpec struct {
	local              byte
	start              uint64
	interval, duration uint32
	schedule           uint32
	data               [8]byte
	enabled            byte
	random             uint32
	id                 string
}

func (w *blob) timed(t timedSpec) {
	w.record()
	w.slotU16(recordTimed)
	w.boundary(t.local, t.start)
	w.boundary(0, 0)
	w.raw(make([]byte, 16)...)
	for _, v := range []uint32{t.interval, t.duration, unsetSeconds, t.schedule} {
		w.le32(v)
	}
	w.raw(t.data[:]...)
	w.raw(0, t.enabled, 0xE9, 0, 1, 0, 0, 0)
	w.le32(t.random)
	w.pad()
	w.packed(utf16le(t.id))
}

func (w *blob) eventDriven(tag uint16, enabled byte, id string) {
	w.record()
	w.slotU16(tag)
	w.boundary(0, 0)
	w.boundary(0, ^uint64(0))
	w.raw(0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF)
	w.raw(make([]byte, 16)...)
	w.raw(enabled, 0x31, 0x32, 0x34, 3, 2, 0, 0)
	w.raw(make([]byte, 8)...)
	w.packed(utf16le(id))
}

func (w *blob) wnf(name [8]byte, data []byte) {
	w.eventDriven(recordWnf, 1, "")
	w.raw(name[:]...)
	w.le32(uint32(len(data)))
	w.raw(0, 0, 0, 0)
	w.raw(data...)
}

func (w *blob) event(query string, tail byte) {
	w.eventDriven(recordEvent, 1, "")
	w.le64(uint64(len([]rune(query))))
	w.raw(utf16le(query)...)
	w.raw(0, 0)
	w.pad()
	w.raw(make([]byte, 24)...)
	w.b[len(w.b)-1] = tail
}

func actionsValue(format uint16, context string, records ...[]byte) []byte {
	var w blob
	w.le16(format)
	w.runText(context)
	for _, r := range records {
		w.raw(r...)
	}
	return w.b
}

func (w *blob) runText(s string) {
	p := utf16le(s)
	w.le32(uint32(len(p)))
	w.raw(p...)
}

func execRecord(format uint16, id, command, args, dir string) []byte {
	var w blob
	w.le16(recordExec)
	for _, s := range []string{id, command, args, dir} {
		w.runText(s)
	}
	if format == actionFormatLate {
		w.le16(0)
	}
	return w.b
}

func comRecord(classID [16]byte, data string) []byte {
	var w blob
	w.le16(recordComHandler)
	w.runText("")
	w.raw(classID[:]...)
	w.runText(data)
	return w.b
}

func dynamicInfo(format uint32, registered, lastRun uint64, result uint32, last uint64) []byte {
	var w blob
	w.le32(format)
	w.le64(registered)
	w.le64(lastRun)
	w.le32(0)
	w.le32(result)
	w.le64(last)
	return w.b
}
