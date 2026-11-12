package autoload

import (
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

func writeNote(buf []byte, at int, nameSize, descSize, noteType uint32, desc string) {
	binary.LittleEndian.PutUint32(buf[at:], nameSize)
	binary.LittleEndian.PutUint32(buf[at+4:], descSize)
	binary.LittleEndian.PutUint32(buf[at+8:], noteType)
	copy(buf[at+12:], noteName)
	copy(buf[at+24:], desc)
}

func kernelNote(buf []byte, at int, desc string) {
	writeNote(buf, at, noteNameSize, uint32(len(desc)), 0, desc)
}

const sampleTable = "OSRELEASE=6.17.0-8-generic\n" +
	"BUILD-ID=4f2a9c0e11d35b7a8c6e0f1d2b3a4c5d6e7f8091\n" +
	"PAGESIZE=4096\n" +
	"SYMBOL(init_uts_ns)=ffffffff9a4171c0\n" +
	"OFFSET(uts_namespace.name)=0\n" +
	"SYMBOL(swapper_pg_dir)=ffffffff9a20c000\n" +
	"SIZE(list_head)=16\n" +
	"LENGTH(mem_section)=2048\n" +
	"NUMBER(VMALLOC_START)=0xffffc90000000000\n" +
	"NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE)=-128\n" +
	"NUMBER(phys_base)=-1048576\n" +
	"SYMBOL(init_top_pgt)=ffffffff9a20c000\n" +
	"NUMBER(pgtable_l5_enabled)=1\n" +
	"KERNELOFFSET=19000000\n" +
	"NUMBER(KERNEL_IMAGE_SIZE)=1073741824\n" +
	"NUMBER(sme_mask)=0\n" +
	"NUMBER(MAX_PHYSMEM_BITS)=52\n" +
	"CONFIG_NUMA=y\n" +
	"CRASHTIME=1762862400\n"

func scanBytes(t *testing.T, buf []byte) (VMCoreInfoScan, error) {
	t.Helper()
	return ScanVMCoreInfo(&flatImage{buf: buf}, limits.Limits{})
}

func oneTable(t *testing.T, desc string) VMCoreInfo {
	t.Helper()
	buf := make([]byte, 0x2000)
	kernelNote(buf, 0x40, desc)
	scan, err := scanBytes(t, buf)
	if err != nil || len(scan.Tables) != 1 || len(scan.Damaged) != 0 {
		t.Fatalf("scan gave %d tables, damage %v, error %v; want one clean table", len(scan.Tables), scan.Damaged, err)
	}
	return scan.Tables[0]
}

func TestANoteInTheKernelsLayoutIsRead(t *testing.T) {
	table := oneTable(t, sampleTable)
	if table.Offset != 0x40 {
		t.Errorf("offset 0x%x, want the header at 0x40", table.Offset)
	}
	ints := map[string]string{
		"PAGESIZE":                          "4096",
		"SYMBOL(swapper_pg_dir)":            "18446744072000421888",
		"OFFSET(uts_namespace.name)":        "0",
		"SIZE(list_head)":                   "16",
		"LENGTH(mem_section)":               "2048",
		"NUMBER(VMALLOC_START)":             "18446683600570023936",
		"NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE)": "-128",
		"NUMBER(phys_base)":                 "-1048576",
		"KERNELOFFSET":                      "419430400",
		"CRASHTIME":                         "1762862400",
	}
	for key, want := range ints {
		e, ok := table.Lookup(key)
		if !ok || e.Int == nil || e.Int.String() != want || e.Cut {
			t.Errorf("%s = %+v, want the number %s", key, e, want)
		}
	}
	for key, want := range map[string]string{"OSRELEASE": "6.17.0-8-generic", "CONFIG_NUMA": "y",
		"BUILD-ID": "4f2a9c0e11d35b7a8c6e0f1d2b3a4c5d6e7f8091"} {
		if e, ok := table.Lookup(key); !ok || e.Int != nil || e.Text != want {
			t.Errorf("%s = %+v, want the text %q", key, e, want)
		}
	}
	if len(table.Entries) != strings.Count(sampleTable, "\n") || table.Entries[0].Key != "OSRELEASE" {
		t.Errorf("%d entries starting %q, want one per line in order", len(table.Entries), table.Entries[0].Key)
	}
}

func TestBytesThatAreNotTheKernelsNoteAreSkippedSilently(t *testing.T) {
	desc := "OSRELEASE=6.17.0\n"
	for _, tc := range []struct {
		name  string
		write func(buf []byte)
	}{
		{"name size 10", func(b []byte) { writeNote(b, 0x40, 10, uint32(len(desc)), 0, desc) }},
		{"type 1", func(b []byte) { writeNote(b, 0x40, noteNameSize, uint32(len(desc)), 1, desc) }},
		{"empty descriptor", func(b []byte) { writeNote(b, 0x40, noteNameSize, 0, 0, desc) }},
		{"descriptor past the bound", func(b []byte) { writeNote(b, 0x40, noteNameSize, x86PageBytes+1, 0, desc) }},
		{"no OSRELEASE first", func(b []byte) { kernelNote(b, 0x40, "PAGESIZE=4096\nOSRELEASE=6.17.0\n") }},
		{"name with no room for a header", func(b []byte) { copy(b[4:], noteName+desc) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 0x1000)
			tc.write(buf)
			scan, err := scanBytes(t, buf)
			if err != nil || len(scan.Tables) != 0 || len(scan.Damaged) != 0 {
				t.Errorf("got tables %+v, damage %v, error %v; want nothing at all", scan.Tables, scan.Damaged, err)
			}
		})
	}
}

func TestADamagedCopyIsReportedAtItsHeader(t *testing.T) {
	long := "OFFSET(" + strings.Repeat("x", 70) + ")"
	for _, tc := range []struct{ name, desc, reason string }{
		{"control byte", "OSRELEASE=6.17\nA=\x01\n", "byte 0x01 at descriptor offset 17 is not text"},
		{"high byte", "OSRELEASE=6.17\nA=\xe9\n", "byte 0xe9"},
		{"NUL in the release", "OSRELEASE=6.17\x00\n", "byte 0x00 at descriptor offset 14 is not text"},
		{"empty line", "OSRELEASE=6.17\n\nPAGESIZE=4096\n", "line 2 is empty"},
		{"79 bytes then a newline", "OSRELEASE=6.17\n" + long + "=\n", "line 3 is empty"},
		{"no equals sign", "OSRELEASE=6.17\nGARBAGE\n", "line 2 has no '='"},
		{"uppercase hex", "OSRELEASE=6.17\nSYMBOL(x)=FFFF\n", `line 2: SYMBOL(x) value "FFFF" is not`},
		{"prefixed hex symbol", "OSRELEASE=6.17\nSYMBOL(x)=0x10\n", `line 2: SYMBOL(x) value "0x10"`},
		{"leading zero", "OSRELEASE=6.17\nSIZE(x)=016\n", `line 2: SIZE(x) value "016"`},
		{"negative size", "OSRELEASE=6.17\nSIZE(x)=-1\n", `line 2: SIZE(x) value "-1"`},
		{"minus zero", "OSRELEASE=6.17\nNUMBER(x)=-0\n", `line 2: NUMBER(x) value "-0"`},
		{"plus sign", "OSRELEASE=6.17\nPAGESIZE=+4096\n", `line 2: PAGESIZE value "+4096"`},
		{"symbol past 64 bits", "OSRELEASE=6.17\nSYMBOL(x)=10000000000000000\n", `line 2: SYMBOL(x) value "10000000000000000" is not 64-bit`},
		{"number past 64 bits", "OSRELEASE=6.17\nNUMBER(x)=9223372036854775808\n", `line 2: NUMBER(x) value "9223372036854775808" is not 64-bit`},
		{"descriptor larger than its page", "OSRELEASE=6.17\nPAGESIZE=16\n", "0x1b-byte descriptor exceeds PAGESIZE 16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 0x1000)
			kernelNote(buf, 0x80, tc.desc)
			scan, err := scanBytes(t, buf)
			var damage *VMCoreInfoDamageError
			if len(scan.Tables) != 0 || len(scan.Damaged) != 1 || scan.Damaged[0].Offset != 0x80 || !errors.As(err, &damage) {
				t.Fatalf("got tables %+v, damage %v, error %v; want one damaged copy at 0x80", scan.Tables, scan.Damaged, err)
			}
			want := "autoload: skipped VMCOREINFO at 0x80: " + tc.reason
			if got := scan.Damaged[0].String(); !strings.HasPrefix(got, want) {
				t.Errorf("diagnostic %q, want it to start %q", got, want)
			}
		})
	}
}

func TestALineLongerThanOneCallIsCut(t *testing.T) {
	long := "OFFSET(" + strings.Repeat("x", 70) + ")=123"
	table := oneTable(t, "OSRELEASE=6.17\n"+long[:noteCallBytes]+"PAGESIZE=4096\nSIZE(page)=64")
	want := []VMCoreInfoEntry{
		{Key: "OSRELEASE", Text: "6.17"},
		{Key: long[:78], Text: "", Cut: true},
		{Key: "PAGESIZE", Text: "4096", Int: big.NewInt(4096)},
		{Key: "SIZE(page)", Text: "64", Cut: true},
	}
	if !reflect.DeepEqual(table.Entries, want) {
		t.Errorf("entries %+v\nwant %+v", table.Entries, want)
	}
}

func TestTheReleaseKeepsItsUnprintableBytesEscaped(t *testing.T) {
	table := oneTable(t, "OSRELEASE=6.17\x01-caf\xc3\xa9\x7f\nPAGESIZE=4096\n")
	if e, _ := table.Lookup("OSRELEASE"); e.Text != `6.17\x01-caf\xc3\xa9\x7f` || e.Cut {
		t.Errorf("release %+v", e)
	}
	table = oneTable(t, "OSRELEASE=6.17\\x01-a\\b\x01\nPAGESIZE=4096\n")
	if e, _ := table.Lookup("OSRELEASE"); e.Text != `6.17\\x01-a\\b\x01` {
		t.Errorf("a backslash in the release is not doubled: %+v", e)
	}
	table = oneTable(t, "OSRELEASE="+strings.Repeat("\xe9", 69)+"PAGESIZE=4096\n")
	if e, _ := table.Lookup("OSRELEASE"); e.Text != strings.Repeat(`\xe9`, 69) || !e.Cut {
		t.Errorf("a release past one call is cut by bytes: %+v", e)
	}
}

func TestAKeyHeldTwiceKeepsItsFirstValue(t *testing.T) {
	table := oneTable(t, "OSRELEASE=6.17\nPAGESIZE=4096\nPAGESIZE=8192\n")
	if e, _ := table.Lookup("PAGESIZE"); len(table.Entries) != 2 || e.Text != "4096" {
		t.Errorf("entries %+v, want PAGESIZE once, as 4096", table.Entries)
	}
}

func TestTheStepDoesNotChangeWhatIsFound(t *testing.T) {
	buf := make([]byte, 0x3000)
	kernelNote(buf, 0x0fee, "OSRELEASE=6.17\n")
	kernelNote(buf, 0x1ff4, sampleTable)
	kernelNote(buf, 0x2800, "OSRELEASE=6.17\nBAD\n")
	r := &flatImage{buf: buf}
	whole, wholeErr := noteScan{step: 0x10000, descBound: x86PageBytes, candidates: 100}.run(r)
	if len(whole.Tables) != 2 || len(whole.Damaged) != 1 || wholeErr != nil {
		t.Fatalf("one window gave %d tables, damage %v, error %v; want 2 and 1", len(whole.Tables), whole.Damaged, wholeErr)
	}
	for _, step := range []uint64{0x10, 0x1000, 0x1001, 0x2004, 0x2005} {
		got, err := noteScan{step: step, descBound: x86PageBytes, candidates: 100}.run(r)
		if !reflect.DeepEqual(got, whole) || err != nil {
			t.Errorf("step 0x%x gave %+v, %v; want the one-window result", step, got, err)
		}
	}
}

type gappedImage struct {
	buf      []byte
	from, to uint64
}

func (m *gappedImage) ReadAt(offset, size uint64) ([]byte, error) {
	if offset < m.to && offset+size > m.from {
		return nil, memory.ErrUnmapped
	}
	return (&flatImage{buf: m.buf}).ReadAt(offset, size)
}

func (m *gappedImage) Size() uint64 { return uint64(len(m.buf)) }

func TestAnUnreadableWindowIsRecordedAndTheRestScanned(t *testing.T) {
	buf := make([]byte, 0x4000)
	kernelNote(buf, 0x3000, "OSRELEASE=6.17\n")
	r := &gappedImage{buf: buf, from: 0x1100, to: 0x1800}
	scan, err := noteScan{step: 0x1000, descBound: x86PageBytes, candidates: 100}.run(r)
	if err != nil || len(scan.Tables) != 1 || scan.Tables[0].Offset != 0x3000 {
		t.Fatalf("got %+v, %v; want the table at 0x3000", scan, err)
	}
	if len(scan.Damaged) != 1 || scan.Damaged[0].Offset != 0x1000 || !errors.Is(scan.Damaged[0].Err, memory.ErrUnmapped) {
		t.Errorf("damage %v, want the window at 0x1000, wrapping the read error", scan.Damaged)
	}
}

func TestTheCandidateLimitSkipsTheRestOfAWindow(t *testing.T) {
	buf := make([]byte, 0x1000)
	kernelNote(buf, 0x100, "OSRELEASE=6.17\n")
	kernelNote(buf, 0x200, "OSRELEASE=6.18\n")
	scan, err := noteScan{step: 0x1000, descBound: x86PageBytes, candidates: 1}.run(&flatImage{buf: buf})
	if err != nil || len(scan.Tables) != 1 || len(scan.Damaged) != 1 || scan.Damaged[0].Offset != 0x20c {
		t.Errorf("got %+v, %v; want the first table and a skip at the second name", scan, err)
	}
}

func TestTheDescriptorBoundFollowsTheTextLimit(t *testing.T) {
	buf := make([]byte, 0x1000)
	kernelNote(buf, 0x40, sampleTable)
	scan, err := ScanVMCoreInfo(&flatImage{buf: buf}, limits.Limits{MaxNameBytes: 32, MaxTextBytes: 64})
	if err != nil || len(scan.Tables) != 0 || len(scan.Damaged) != 0 {
		t.Errorf("got %+v, %v; want a descriptor past 64 bytes skipped", scan, err)
	}
}

func layoutTable(t *testing.T, change func(map[string]string)) VMCoreInfo {
	t.Helper()
	keys := map[string]string{
		"SYMBOL(swapper_pg_dir)":     "ffffffff9a20c000",
		"SYMBOL(init_top_pgt)":       "ffffffff9a20c000",
		"NUMBER(phys_base)":          "-1048576",
		"KERNELOFFSET":               "19000000",
		"NUMBER(KERNEL_IMAGE_SIZE)":  "1073741824",
		"NUMBER(pgtable_l5_enabled)": "1",
		"NUMBER(MAX_PHYSMEM_BITS)":   "52",
		"NUMBER(sme_mask)":           "140737488355328",
	}
	if change != nil {
		change(keys)
	}
	desc := "OSRELEASE=6.17.0\n"
	for k, v := range keys {
		desc += k + "=" + v + "\n"
	}
	return oneTable(t, desc)
}

func TestTheLayoutComesFromTheX8664Keys(t *testing.T) {
	got, err := layoutTable(t, nil).KernelLayout()
	want := VMCoreInfoLayout{VirtualShift: 0x19000000, PhysBase: -0x100000, DTB: 0x1a20c000 - 0x100000,
		FiveLevel: true, PhysAddrBits: 52, SMEMask: 1 << 47}
	if err != nil || got != want {
		t.Errorf("layout %+v, %v; want %+v", got, err, want)
	}

	got, err = layoutTable(t, func(k map[string]string) {
		for _, key := range []string{"SYMBOL(init_top_pgt)", "NUMBER(KERNEL_IMAGE_SIZE)", "NUMBER(pgtable_l5_enabled)",
			"NUMBER(MAX_PHYSMEM_BITS)", "NUMBER(sme_mask)"} {
			delete(k, key)
		}
		k["NUMBER(phys_base)"] = "33554432"
	}).KernelLayout()
	want = VMCoreInfoLayout{VirtualShift: 0x19000000, PhysBase: 0x2000000, DTB: 0x1a20c000 + 0x2000000}
	if err != nil || got != want {
		t.Errorf("layout without the optional keys %+v, %v; want %+v", got, err, want)
	}
}

func TestEachLayoutRuleRefusesATable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]string)
		reason string
	}{
		{"PAE build", func(k map[string]string) { k["CONFIG_X86_PAE"] = "y" }, "describes a 32-bit kernel (PAE)"},
		{"no page table", func(k map[string]string) { delete(k, "SYMBOL(swapper_pg_dir)") }, "no SYMBOL(swapper_pg_dir)"},
		{"32-bit page table", func(k map[string]string) { k["SYMBOL(swapper_pg_dir)"] = "c1a0c000" }, "describes a 32-bit kernel"},
		{"no phys_base", func(k map[string]string) { delete(k, "NUMBER(phys_base)") }, "NUMBER(phys_base)"},
		{"no offset", func(k map[string]string) { delete(k, "KERNELOFFSET") }, "no KERNELOFFSET"},
		{"mapping too large", func(k map[string]string) { k["NUMBER(KERNEL_IMAGE_SIZE)"] = "2147483648" }, "NUMBER(KERNEL_IMAGE_SIZE)"},
		{"mapping zero", func(k map[string]string) { k["NUMBER(KERNEL_IMAGE_SIZE)"] = "0" }, "NUMBER(KERNEL_IMAGE_SIZE)"},
		{"page table past a small mapping", func(k map[string]string) { k["NUMBER(KERNEL_IMAGE_SIZE)"] = "268435456" },
			"is outside the kernel image mapping"},
		{"page table below the map", func(k map[string]string) {
			k["SYMBOL(swapper_pg_dir)"], k["SYMBOL(init_top_pgt)"] = "ffff88801a20c000", "ffff88801a20c000"
		}, "is outside the kernel image mapping"},
		{"init_top_pgt elsewhere", func(k map[string]string) { k["SYMBOL(init_top_pgt)"] = "ffffffff9a20d000" }, "differs"},
		{"negative page table", func(k map[string]string) { k["NUMBER(phys_base)"] = "-1073741824" }, "page table"},
		{"unaligned page table", func(k map[string]string) { k["NUMBER(phys_base)"] = "-1048064" }, "page table"},
		{"offset off 2 MiB", func(k map[string]string) { k["KERNELOFFSET"] = "19001000" }, "KERNELOFFSET 0x19001000"},
		{"offset past the mapping", func(k map[string]string) { k["KERNELOFFSET"] = "40000000" }, "KERNELOFFSET 0x40000000"},
		{"paging flag 2", func(k map[string]string) { k["NUMBER(pgtable_l5_enabled)"] = "2" }, "neither 0 nor 1"},
		{"physical bits 12", func(k map[string]string) { k["NUMBER(MAX_PHYSMEM_BITS)"] = "12" }, "NUMBER(MAX_PHYSMEM_BITS) 12"},
		{"physical bits 53", func(k map[string]string) { k["NUMBER(MAX_PHYSMEM_BITS)"] = "53" }, "NUMBER(MAX_PHYSMEM_BITS) 53"},
		{"negative sme mask", func(k map[string]string) { k["NUMBER(sme_mask)"] = "-1" }, "NUMBER(sme_mask) -1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := layoutTable(t, tc.change)
			_, err := table.KernelLayout()
			if err == nil || !strings.HasPrefix(err.Error(), "autoload: VMCOREINFO at 0x40: ") ||
				!strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %v, want one at 0x40 naming %q", err, tc.reason)
			}
		})
	}
}

func TestACutLineGivesTheLayoutNoValue(t *testing.T) {
	table := VMCoreInfo{Offset: 0x40, Entries: []VMCoreInfoEntry{
		{Key: "SYMBOL(swapper_pg_dir)", Text: "ffffffff9a20c000", Int: new(big.Int).SetUint64(0xffffffff9a20c000), Cut: true},
	}}
	if _, err := table.KernelLayout(); err == nil || !strings.Contains(err.Error(), "no SYMBOL(swapper_pg_dir)") {
		t.Errorf("error %v, want the cut page-table line treated as absent", err)
	}
}

func FuzzScanVMCoreInfo(f *testing.F) {
	img := make([]byte, 0x1000)
	kernelNote(img, 0x30, sampleTable)
	kernelNote(img, 0x500, "OSRELEASE=6.14.5\nPAGESIZE=4096\nPAGESIZE=8192\n")
	kernelNote(img, 0x700, "OSRELEASE=6.14.5\nX\n")
	f.Add(img, uint16(0x40))
	f.Add(img, uint16(0x3f0))

	f.Fuzz(func(t *testing.T, data []byte, step uint16) {
		r := &flatImage{buf: data}
		whole, wholeErr := noteScan{step: uint64(len(data)) + 1, descBound: x86PageBytes, candidates: len(data) + 1}.run(r)
		windowed, err := noteScan{step: 16 + uint64(step)%0x1000, descBound: x86PageBytes, candidates: len(data) + 1}.run(r)
		if (err == nil) != (wholeErr == nil) || !reflect.DeepEqual(windowed, whole) {
			t.Fatalf("step 0x%x found %+v (%v); one window found %+v (%v)", 16+int(step)%0x1000, windowed, err, whole, wholeErr)
		}
		for _, table := range whole.Tables {
			if string(data[table.Offset+noteHeaderSize:table.Offset+2*noteHeaderSize]) != noteName {
				t.Fatalf("table at 0x%x has no note name after its header", table.Offset)
			}
			if table.Entries[0].Key != "OSRELEASE" {
				t.Fatalf("table at 0x%x opens with %q", table.Offset, table.Entries[0].Key)
			}
			seen := map[string]bool{}
			for _, e := range table.Entries {
				if seen[e.Key] {
					t.Fatalf("table at 0x%x holds %s twice", table.Offset, e.Key)
				}
				seen[e.Key] = true
			}
		}
	})
}

func unescapeRelease(text string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' {
			out.WriteByte(text[i])
			continue
		}
		switch {
		case i+1 < len(text) && text[i+1] == '\\':
			out.WriteByte('\\')
			i++
		case i+3 < len(text) && text[i+1] == 'x':
			var b byte
			for _, h := range text[i+2 : i+4] {
				switch {
				case h >= '0' && h <= '9':
					b = b<<4 | byte(h-'0')
				case h >= 'a' && h <= 'f':
					b = b<<4 | byte(h-'a'+10)
				default:
					return "", false
				}
			}
			out.WriteByte(b)
			i += 3
		default:
			return "", false
		}
	}
	return out.String(), true
}

func FuzzParseNoteTable(f *testing.F) {
	f.Add([]byte("OSRELEASE=6.17\\x41\\\x01\x7f\n"))
	f.Add([]byte(sampleTable))
	f.Add([]byte("OSRELEASE=6\nNUMBER(x)=0x10\nNUMBER(y)=-5\nSIZE(z)=10\nA=1\nA=2\nB=3"))
	f.Add([]byte("OSRELEASE=6\n" + strings.Repeat("k", 100) + "=1\n"))

	f.Fuzz(func(t *testing.T, desc []byte) {
		entries, err := parseNoteTable(desc)
		if err != nil {
			if entries != nil {
				t.Fatalf("error %v came with %d entries", err, len(entries))
			}
			return
		}
		seen := map[string]bool{}
		for i, e := range entries {
			if seen[e.Key] {
				t.Fatalf("%s held twice", e.Key)
			}
			seen[e.Key] = true
			for _, c := range []byte(e.Text) {
				if c < 0x20 || c > 0x7e {
					t.Fatalf("%s=%q holds byte 0x%02x", e.Key, e.Text, c)
				}
			}
			if i == 0 && e.Key == "OSRELEASE" {
				if raw, ok := unescapeRelease(e.Text); !ok || raw != string(desc[len(noteFirstKey):releaseLineEnd(desc)]) {
					t.Fatalf("release %q does not read back to its bytes", e.Text)
				}
				continue
			}
			if strings.ContainsAny(e.Key, "=\n") || strings.Contains(e.Text, "\n") ||
				len(e.Key)+1+len(e.Text) > noteCallBytes {
				t.Fatalf("entry %q=%q crosses a line, its '=' or one call's bytes", e.Key, e.Text)
			}
			format := formatOf(e.Key)
			if numeric := format != formatText && !e.Cut; numeric != (e.Int != nil) {
				t.Fatalf("%s=%q (cut %v) parsed as %v", e.Key, e.Text, e.Cut, e.Int)
			}
			if e.Int != nil {
				again, ok := format.parse(e.Text)
				if !ok || again.Cmp(e.Int) != 0 || !e.Int.IsInt64() && !e.Int.IsUint64() {
					t.Fatalf("%s=%q does not round-trip: %v", e.Key, e.Text, e.Int)
				}
			}
		}
	})
}

// depthImage holds tables at 0x1000 that map one 2-MiB page in the upper
// half, through four levels or five.
func depthImage(levels int) *flatImage {
	m := &flatImage{buf: make([]byte, 0x10000)}
	put := func(table, index, value uint64) { binary.LittleEndian.PutUint64(m.buf[table+8*index:], value) }
	const present, write, large = 1, 2, 1 << 7
	table := uint64(0x1000)
	for i := 0; i < levels-2; i++ {
		put(table, 511-uint64(i%2), table+0x1000|present|write)
		table += 0x1000
	}
	put(table, 8, 0x1200000|large|present|write)
	return m
}

func depthTable(t *testing.T, extra string) (VMCoreInfo, VMCoreInfoLayout) {
	t.Helper()
	table := oneTable(t, "OSRELEASE=4.15.0\nSYMBOL(swapper_pg_dir)=ffffffff80001000\nNUMBER(phys_base)=0\nKERNELOFFSET=0\n"+extra)
	layout, err := table.KernelLayout()
	if err != nil {
		t.Fatal(err)
	}
	return table, layout
}

func TestWithoutTheFlagTheDepthComesFromTheTables(t *testing.T) {
	table, layout := depthTable(t, "")
	for levels, five := range map[int]bool{4: false, 5: true} {
		got, err := table.ConfirmDepth(depthImage(levels), layout)
		if err != nil || got.FiveLevel != five || got.DepthEvidence == "" {
			t.Errorf("%d-level tables: five %v, evidence %q, err %v", levels, got.FiveLevel, got.DepthEvidence, err)
		}
	}
	empty := &flatImage{buf: make([]byte, 0x10000)}
	binary.LittleEndian.PutUint64(empty.buf[0x1000+8*511:], 0x2000|1)
	got, err := table.ConfirmDepth(empty, layout)
	if err == nil || got.FiveLevel || !strings.Contains(err.Error(), "read as 4-level") || !strings.Contains(err.Error(), "undecided") {
		t.Errorf("undecided tables: five %v, err %v", got.FiveLevel, err)
	}
}

func TestTheFlagDecidesTheDepthWithoutTheTables(t *testing.T) {
	table, layout := depthTable(t, "NUMBER(pgtable_l5_enabled)=0\n")
	got, err := table.ConfirmDepth(depthImage(5), layout)
	if err != nil || got.FiveLevel || got.DepthEvidence != "" {
		t.Errorf("five %v, evidence %q, err %v", got.FiveLevel, got.DepthEvidence, err)
	}
}
