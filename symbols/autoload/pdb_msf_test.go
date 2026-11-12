package autoload

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestStreamsReadBackAcrossBlocksOfEveryBlockSize(t *testing.T) {
	want := [][]byte{nil, bytes.Repeat([]byte("abc"), 700), {}, bytes.Repeat([]byte{7}, 4096)}
	for _, size := range []uint32{512, 1024, 2048, 4096} {
		c, err := readMSF(writeMSF(size, want))
		if err != nil {
			t.Fatalf("block size %d: %v", size, err)
		}
		for i, s := range want {
			if got := c.stream(i); !bytes.Equal(got, s) {
				t.Errorf("block size %d stream %d: %d bytes, want %d", size, i, len(got), len(s))
			}
		}
		if c.stream(len(want)) != nil || c.stream(-1) != nil {
			t.Errorf("block size %d: a stream past the directory reads", size)
		}
	}
}

func TestADirectoryListedOverSeveralBlocksReads(t *testing.T) {
	streams := make([][]byte, 300)
	for i := range streams {
		streams[i] = []byte{byte(i)}
	}
	c, err := readMSF(writeMSF(512, streams))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.stream(299); !bytes.Equal(got, []byte{byte(299 % 256)}) {
		t.Fatalf("stream 299 = %v", got)
	}
}

func superblockField(file []byte, field int, v uint32) []byte {
	out := bytes.Clone(file)
	binary.LittleEndian.PutUint32(out[len(msfSignature)+4*field:], v)
	return out
}

func TestTheSuperblockIsChecked(t *testing.T) {
	file := writeMSF(512, [][]byte{nil, []byte("x")})
	cases := map[string][]byte{
		"no signature":           append([]byte("Microsoft C/C++ program database 2.00\r\n"), file[40:]...),
		"short":                  file[:msfHeaderSize-1],
		"block size 4000":        superblockField(file, 0, 4000),
		"more blocks than file":  superblockField(file, 2, uint32(len(file)/512+1)),
		"map block out of range": superblockField(file, 5, uint32(len(file)/512)),
		"directory of 0 bytes":   superblockField(file, 3, 0),
		"directory map too long": superblockField(file, 3, 512*129),
	}
	for name, data := range cases {
		if _, err := readMSF(data); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := readMSF(cases["no signature"]); !errors.Is(err, errNotMSF) {
		t.Errorf("no signature: %v, want errNotMSF", err)
	}
}

func directoryOf(t *testing.T, file []byte) (dir []byte, at int) {
	t.Helper()
	mapBlock := binary.LittleEndian.Uint32(file[len(msfSignature)+20:])
	first := binary.LittleEndian.Uint32(file[mapBlock*512:])
	return file[first*512 : first*512+512], int(first * 512)
}

func TestADirectoryThatClaimsMoreThanTheFileIsRefused(t *testing.T) {
	file := writeMSF(512, [][]byte{nil, bytes.Repeat([]byte{1}, 600)})
	_, at := directoryOf(t, file)

	huge := bytes.Clone(file)
	binary.LittleEndian.PutUint32(huge[at+8:], 1<<30)
	if _, err := readMSF(huge); err == nil {
		t.Error("a stream of 1 GiB in a small file was read")
	}

	badBlock := bytes.Clone(file)
	binary.LittleEndian.PutUint32(badBlock[at+12:], 1<<20)
	if _, err := readMSF(badBlock); err == nil {
		t.Error("a stream naming a block past the file was read")
	}

	many := bytes.Clone(file)
	binary.LittleEndian.PutUint32(many[at:], 1<<20)
	if _, err := readMSF(many); err == nil {
		t.Error("a directory listing more streams than it holds was read")
	}
}

func TestAnAbsentStreamReadsAsNone(t *testing.T) {
	file := writeMSF(512, [][]byte{nil, []byte("x")})
	_, at := directoryOf(t, file)
	binary.LittleEndian.PutUint32(file[at+8:], msfAbsentStream)
	c, err := readMSF(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.stream(1) != nil {
		t.Fatal("an absent stream read as bytes")
	}
}

func FuzzReadMSF(f *testing.F) {
	f.Add(writeMSF(512, [][]byte{nil, []byte("info"), bytes.Repeat([]byte{2}, 1100)}))
	f.Add(newFixture().file())
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := readMSF(data)
		if err != nil {
			return
		}
		total := 0
		for i := range c.sizes {
			s := c.stream(i)
			total += len(s)
			if c.sizes[i] != msfAbsentStream && uint32(len(s)) != c.sizes[i] {
				t.Fatalf("stream %d is %d bytes, the directory says %d", i, len(s), c.sizes[i])
			}
		}
		if total > len(data) {
			t.Fatalf("streams hold %d bytes, more than the %d-byte file", total, len(data))
		}
	})
}
