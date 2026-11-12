package executioncompatcache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.execution.read_compat_cache"

var (
	ErrNoValue     = errors.New("executioncompatcache: AppCompatCache value not found")
	ErrValueUnread = errors.New("executioncompatcache: AppCompatCache value data not resident")
	ErrHeader      = errors.New("executioncompatcache: header size not measured")
	ErrRecord      = errors.New("executioncompatcache: record does not decode")
	ErrIncomplete  = errors.New("executioncompatcache: value not read in full")
)

const (
	cacheKey   = `Control\Session Manager\AppCompatCache`
	cacheValue = "AppCompatCache"
)

const recordSignature = 0x73743031

const recordHeaderBytes = 12

var measuredHeaders = map[uint32]bool{0x30: true, 0x34: true}

type CacheRecord struct {
	Position      int
	Offset        int
	Key           string
	FileLastWrite time.Time
	DataSize      uint32
	Data          []byte
	ChecksumValid bool
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Decode the AppCompatCache value the compatibility cache last wrote to the SYSTEM hive: each record's key, file last-write time, data and checksum, most recent first",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]CacheRecord, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	hive, err := registryhive.OpenHive(ctx, "SYSTEM", nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	key, err := hive.OpenKey(registryhive.CurrentControlSet(hive) + `\` + cacheKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	values, complete := hive.ValuesChecked(key)
	v, found, maybe := registryhive.FindValue(values, complete, cacheValue)
	switch {
	case maybe:
		return nil, fmt.Errorf("%s: key at 0x%x: %w", Name, key.Address, ErrIncomplete)
	case !found:
		return nil, fmt.Errorf("%s: key at 0x%x: %w", Name, key.Address, ErrNoValue)
	case len(v.Raw) == 0:
		return nil, fmt.Errorf("%s: key at 0x%x: %w", Name, key.Address, ErrValueUnread)
	}
	records, err := DecodeRecords(v.Raw)
	if err != nil && !errors.Is(err, ErrRecord) {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var firstErr error
	if err != nil {
		ctx.AddDiagnostic("%s: value at 0x%x: %v", Name, key.Address, err)
		firstErr = fmt.Errorf("%s: %w", Name, err)
	}
	if v.Unreadable() {
		ctx.AddDiagnostic("%s: value at 0x%x: %d of %d bytes read: %v", Name, key.Address, len(v.Raw), v.Length, ErrIncomplete)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: value at 0x%x: %w", Name, key.Address, ErrIncomplete)
		}
	}
	if firstErr != nil && ctx.StrictMode() {
		return records, firstErr
	}
	return records, nil
}

// The record walk ends where the bytes stop holding a record; a value cut at
// a missing page therefore ends early, and the caller reports the cut.
func DecodeRecords(raw []byte) ([]CacheRecord, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("%d bytes: %w", len(raw), ErrHeader)
	}
	header := binary.LittleEndian.Uint32(raw)
	if !measuredHeaders[header] || uint64(header) > uint64(len(raw)) {
		return nil, fmt.Errorf("header 0x%x: %w", header, ErrHeader)
	}
	var out []CacheRecord
	pos := int(header)
	for pos+recordHeaderBytes <= len(raw) {
		if binary.LittleEndian.Uint32(raw[pos:]) != recordSignature {
			return out, fmt.Errorf("offset 0x%x: signature: %w", pos, ErrRecord)
		}
		crc := binary.LittleEndian.Uint32(raw[pos+4:])
		size := uint64(binary.LittleEndian.Uint32(raw[pos+8:]))
		if size > uint64(len(raw)-pos-recordHeaderBytes) {
			return out, fmt.Errorf("offset 0x%x: payload of %d bytes past the end: %w", pos, size, ErrRecord)
		}
		payload := raw[pos+recordHeaderBytes : pos+recordHeaderBytes+int(size)]
		r, err := decodePayload(payload)
		if err != nil {
			return out, fmt.Errorf("offset 0x%x: %w", pos, err)
		}
		r.Position, r.Offset = len(out), pos
		r.ChecksumValid = crc32.ChecksumIEEE(payload) == crc
		out = append(out, r)
		pos += recordHeaderBytes + int(size)
	}
	if pos != len(raw) {
		return out, fmt.Errorf("offset 0x%x: %d bytes left: %w", pos, len(raw)-pos, ErrRecord)
	}
	return out, nil
}

func decodePayload(p []byte) (CacheRecord, error) {
	if len(p) < 2 {
		return CacheRecord{}, fmt.Errorf("key length: %w", ErrRecord)
	}
	keyLen := int(binary.LittleEndian.Uint16(p))
	if keyLen%2 != 0 || 2+keyLen+12 > len(p) {
		return CacheRecord{}, fmt.Errorf("key of %d bytes: %w", keyLen, ErrRecord)
	}
	r := CacheRecord{Key: util.DecodeUTF16LE(p[2 : 2+keyLen])}
	at := 2 + keyLen
	r.FileLastWrite, _ = util.FiletimeToTime(binary.LittleEndian.Uint64(p[at:]))
	r.DataSize = binary.LittleEndian.Uint32(p[at+8:])
	rest := p[at+12:]
	if uint64(r.DataSize) != uint64(len(rest)) {
		return CacheRecord{}, fmt.Errorf("data of %d bytes in %d: %w", r.DataSize, len(rest), ErrRecord)
	}
	r.Data = append([]byte(nil), rest...)
	return r, nil
}
