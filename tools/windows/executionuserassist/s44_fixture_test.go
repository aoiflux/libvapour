package executionuserassist

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

// The fixtures follow spec S44 section 3.3 (L1 to L4) and the constant words
// of M6.
const (
	programsGUID  = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"
	shortcutsGUID = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
	emptyGUID     = "{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}"
	systemPrefix  = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
	systemX86     = "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"
	programsMenu  = "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"
)

func countData(launches, otherCount, otherWord uint32, lastLaunch uint64) []byte {
	b := make([]byte, countDataSize)
	binary.LittleEndian.PutUint32(b[0x04:], launches)
	binary.LittleEndian.PutUint32(b[0x08:], otherCount)
	binary.LittleEndian.PutUint32(b[0x0C:], otherWord)
	for off := 0x10; off < 0x38; off += 4 {
		binary.LittleEndian.PutUint32(b[off:], math.Float32bits(-1))
	}
	binary.LittleEndian.PutUint32(b[0x38:], 0xFFFFFFFF)
	binary.LittleEndian.PutUint64(b[0x3C:], lastLaunch)
	return b
}

func sessionData() []byte { return make([]byte, 4+12+3*(12+520)) }

func filetime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10_000_000 + uint64(t.Nanosecond()/100)
}

func countValue(name string, data []byte) registryhive.Value {
	return registryhive.Value{Name: rot13(name), Type: 3, Raw: data, Length: uint32(len(data))}
}

type assistFixture struct {
	hive *registrytest.FakeHive
	root *registryhive.KeyNode
}

func newAssistHive() assistFixture {
	h := registrytest.NewFakeHive("ROOT")
	return assistFixture{hive: h, root: h.Path(assistKey)}
}

func (f assistFixture) subkey(guid string, version uint32, values ...registryhive.Value) (g, count *registryhive.KeyNode) {
	g = f.hive.Key(f.root, guid)
	f.hive.Values[g] = []registryhive.Value{registrytest.DWORD("Version", version)}
	count = f.hive.Key(g, "Count")
	f.hive.Values[count] = values
	return g, count
}
