package executionuserassist

import (
	"encoding/binary"
	"errors"
)

var (
	ErrIncomplete = errors.New("executionuserassist: user hive not read in full")
	ErrDataLength = errors.New("executionuserassist: value data length not measured")
	ErrVersion    = errors.New("executionuserassist: subkey version not measured")
	ErrTime       = errors.New("executionuserassist: last launch is not a time")
)

const (
	countDataSize   = 72
	launchCountAt   = 0x04
	lastLaunchAt    = 0x3C
	measuredVersion = 5
)

type CountData struct {
	LaunchCount uint32
	LastLaunch  uint64
}

func DecodeCountData(b []byte) (CountData, error) {
	if len(b) != countDataSize {
		return CountData{}, ErrDataLength
	}
	return CountData{
		LaunchCount: binary.LittleEndian.Uint32(b[launchCountAt:]),
		LastLaunch:  binary.LittleEndian.Uint64(b[lastLaunchAt:]),
	}, nil
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

type decodedName struct {
	name     string
	folder   KnownFolder
	found    bool
	expanded string
}

func decodeName(stored string, wide bool) decodedName {
	d := decodedName{name: rot13(stored)}
	d.expanded = d.name
	guid, rest, ok := splitFolderPrefix(d.name)
	if !ok {
		return d
	}
	d.folder, d.found = LookupKnownFolder(guid, wide)
	if d.found && d.folder.Path != "" {
		d.expanded = d.folder.Path + rest
	}
	return d
}
