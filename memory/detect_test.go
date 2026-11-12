package memory

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"
)

func TestAFileNoDetectorClaimsIsRaw(t *testing.T) {
	for _, data := range []image{image(make([]byte, 4096)), image("PAGEPAGE.."), image("\x7fEL"), nil} {
		r, format, err := DetectFormat(data)
		if err != nil || format != "raw" || r.Size() != data.Size() {
			t.Errorf("%q: %s %v", data[:min(len(data), 8)], format, err)
		}
	}
}

func TestDetectionFollowsTheSignatureNotTheName(t *testing.T) {
	lime := limeFile([]limeRange{{0x1000, pattern(0x1000, 1)}})
	r, format, err := DetectFormat(lime, DefaultDetectors()...)
	if err != nil || format != "lime" || r.Size() != 0x2000 {
		t.Fatalf("lime: %s %v", format, err)
	}
	crash := crashFile([]run{{1, 2}}, nil)
	if _, format, err := DetectFormat(crash); err != nil || format != "crashdump" {
		t.Errorf("crash dump: %s %v", format, err)
	}
	core := elfSpec{wide: true, notes: []elfNoteSpec{{noteVMCore, 0, []byte("OSRELEASE=6.1\n")}},
		loads: []elfLoadSpec{{phys: 0x1000, data: pattern(64, 2)}}}.build()
	if _, format, err := DetectFormat(core); err != nil || format != "elf" {
		t.Errorf("elf core: %s %v", format, err)
	}
}

func TestAClaimedFileThatFailsItsChecksIsNotReadAsRaw(t *testing.T) {
	bad := limeFile([]limeRange{{0x1000, pattern(16, 1)}})
	bad[4] = 2
	if _, _, err := DetectFormat(bad); !errors.Is(err, ErrLime) {
		t.Errorf("damaged lime: %v", err)
	}
	if _, _, err := DetectFormat(nil); err == nil {
		t.Error("no reader detected")
	}
}

type claimNothing struct{}

func (claimNothing) Name() string { return "nothing" }

func (claimNothing) Detect(MemoryReader) (MemoryReader, bool, error) { return nil, true, nil }

func TestADetectorThatClaimsWithoutAReaderIsPassedOver(t *testing.T) {
	_, format, err := DetectFormat(image("x"), claimNothing{}, nil)
	if err != nil || format != "raw" {
		t.Errorf("%s %v", format, err)
	}
}

func zlibStream(t *testing.T, data []byte) image {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return image(b.Bytes())
}

func TestAMinidumpIsRefusedNotReadAsRaw(t *testing.T) {
	file := append(image("MDMP\x93\xa7\x00\x00"), make([]byte, 64)...)
	_, format, err := DetectFormat(file)
	if !errors.Is(err, ErrMinidump) || format != "minidump" {
		t.Errorf("%s %v", format, err)
	}
}

func TestAZlibStreamIsRefusedNotReadAsRaw(t *testing.T) {
	for name, data := range map[string][]byte{"zeros": make([]byte, 1<<20), "short": []byte("a few bytes"), "pattern": pattern(1<<16, 3)} {
		_, format, err := DetectFormat(zlibStream(t, data))
		if !errors.Is(err, ErrCompressed) || format != "zlib" {
			t.Errorf("%s: %s %v", name, format, err)
		}
	}
}

func TestOnlyADecodableRFC1950HeaderIsClaimed(t *testing.T) {
	stream := zlibStream(t, make([]byte, 1<<16))
	dict := append(image{stream[0], 0}, stream[2:]...)
	for dict[1] = 0x20; (uint16(dict[0])<<8|uint16(dict[1]))%31 != 0; dict[1]++ {
	}
	cases := map[string]image{
		"header only":     stream[:2],
		"bad check bits":  append(image{stream[0], stream[1] + 1}, stream[2:]...),
		"window above 7":  append(image{0x88, 0x00}, stream[2:]...),
		"not deflate":     append(image{0x79, 0x00}, stream[2:]...),
		"preset dict":     dict,
		"corrupt deflate": append(image{0x78, 0x9c, 0xff}, make([]byte, 64)...),
	}
	for name, data := range cases {
		if _, format, err := DetectFormat(data); err != nil || format != "raw" {
			t.Errorf("%s: %s %v", name, format, err)
		}
	}
}
