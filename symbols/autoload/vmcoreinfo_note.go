package autoload

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/aoiflux/libvapour/layers"
	"github.com/aoiflux/libvapour/limits"
	"github.com/aoiflux/libvapour/memory"
)

// Constants follow S05: the note layout (K1, K2), the per-call line buffer
// (K4), the x86 page size that bounds the table (K3, K16) and the x86-64
// kernel map (K12 to K15).
const (
	noteName          = "VMCOREINFO\x00\x00"
	noteNameSize      = 11
	noteHeaderSize    = 12
	noteFirstKey      = "OSRELEASE="
	noteCallBytes     = 0x50 - 1
	noteScanStep      = 4 << 20
	x86PageBytes      = 4096
	startKernelMap    = 0xffffffff80000000
	imageMappingMax   = 1 << 30
	kaslrAlignment    = 0x200000
	pageTableAlign    = 4096
	physAddrBitsMax   = 52
	physAddrBitsLeast = 13
)

type VMCoreInfo struct {
	Offset  uint64
	Entries []VMCoreInfoEntry
}

type VMCoreInfoEntry struct {
	Key  string
	Text string
	Int  *big.Int
	Cut  bool
}

func (v VMCoreInfo) Lookup(key string) (VMCoreInfoEntry, bool) {
	for _, e := range v.Entries {
		if e.Key == key {
			return e, true
		}
	}
	return VMCoreInfoEntry{}, false
}

func (v VMCoreInfo) whole(key string) (*big.Int, bool) {
	e, ok := v.Lookup(key)
	if !ok || e.Cut || e.Int == nil {
		return nil, false
	}
	return e.Int, true
}

type VMCoreInfoScan struct {
	Tables  []VMCoreInfo
	Damaged []DamagedVMCoreInfo
}

type DamagedVMCoreInfo struct {
	Offset uint64
	Err    error
}

func (d DamagedVMCoreInfo) String() string {
	return "autoload: skipped " + d.Err.Error()
}

type VMCoreInfoDamageError struct {
	Damaged []DamagedVMCoreInfo
}

func (e *VMCoreInfoDamageError) Error() string {
	parts := make([]string, len(e.Damaged))
	for i, d := range e.Damaged {
		parts[i] = d.Err.Error()
	}
	return fmt.Sprintf("autoload: %d VMCOREINFO copies or ranges skipped: %s", len(e.Damaged), strings.Join(parts, "; "))
}

func (e *VMCoreInfoDamageError) Unwrap() []error {
	errs := make([]error, len(e.Damaged))
	for i, d := range e.Damaged {
		errs[i] = d.Err
	}
	return errs
}

type noteScan struct {
	step       uint64
	descBound  uint64
	candidates int
}

func ScanVMCoreInfo(r memory.MemoryReader, l limits.Limits) (VMCoreInfoScan, error) {
	l = l.Effective()
	return noteScan{
		step:       uint64(min(noteScanStep, l.MaxBufferBytes)),
		descBound:  uint64(min(x86PageBytes, l.MaxTextBytes)),
		candidates: l.MaxMatchesPerChunk,
	}.run(r)
}

func (c noteScan) run(r memory.MemoryReader) (VMCoreInfoScan, error) {
	var scan VMCoreInfoScan
	name := []byte(noteName)
	recorder := &windowFailures{r: r, out: &scan.Damaged}
	memory.ScanWindows(recorder, c.step, uint64(len(name)-1), func(base uint64, window []byte) bool {
		owned := min(c.step, uint64(len(window)))
		found := 0
		for at := uint64(0); at < owned; {
			rel := bytes.Index(window[at:], name)
			if rel < 0 || at+uint64(rel) >= owned {
				break
			}
			hit := at + uint64(rel)
			if found == c.candidates {
				scan.Damaged = append(scan.Damaged, DamagedVMCoreInfo{Offset: base + hit,
					Err: fmt.Errorf("VMCOREINFO scan at 0x%x: more than %d candidate names, rest of window skipped",
						base+hit, c.candidates)})
				break
			}
			found++
			c.candidate(r, base+hit, &scan)
			at = hit + 1
		}
		return false
	})
	if len(scan.Tables) == 0 && len(scan.Damaged) > 0 {
		return scan, &VMCoreInfoDamageError{Damaged: scan.Damaged}
	}
	return scan, nil
}

// The wrapper exists so a window ScanWindows cannot read is reported at its
// own offset instead of vanishing from a not-found result.
type windowFailures struct {
	r   memory.MemoryReader
	out *[]DamagedVMCoreInfo
}

func (f *windowFailures) ReadAt(offset, size uint64) ([]byte, error) {
	b, err := f.r.ReadAt(offset, size)
	if err != nil {
		*f.out = append(*f.out, DamagedVMCoreInfo{Offset: offset,
			Err: fmt.Errorf("VMCOREINFO scan at 0x%x: read 0x%x bytes: %w", offset, size, err)})
	}
	return b, err
}

func (f *windowFailures) Size() uint64 { return f.r.Size() }

func (f *windowFailures) Segments() []memory.Segment {
	ranges := memory.MappedRanges(f.r)
	segments := make([]memory.Segment, len(ranges))
	for i, rng := range ranges {
		segments[i] = memory.Segment{PhysicalBase: rng.Start, FileOffset: rng.Start, Length: rng.End - rng.Start}
	}
	return segments
}

func readExactly(r memory.MemoryReader, offset, size uint64) ([]byte, error) {
	b, err := r.ReadAt(offset, size)
	if err == nil && uint64(len(b)) != size {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

func (c noteScan) candidate(r memory.MemoryReader, nameAt uint64, scan *VMCoreInfoScan) {
	if nameAt < noteHeaderSize {
		return
	}
	at := nameAt - noteHeaderSize
	damaged := func(format string, args ...any) {
		scan.Damaged = append(scan.Damaged, DamagedVMCoreInfo{Offset: at,
			Err: fmt.Errorf("VMCOREINFO at 0x%x: "+format, append([]any{at}, args...)...)})
	}
	header, err := readExactly(r, at, noteHeaderSize)
	if err != nil {
		damaged("read note header: %w", err)
		return
	}
	nameSize := binary.LittleEndian.Uint32(header[0:])
	descSize := uint64(binary.LittleEndian.Uint32(header[4:]))
	noteType := binary.LittleEndian.Uint32(header[8:])
	if nameSize != noteNameSize || noteType != 0 || descSize == 0 || descSize > c.descBound {
		return
	}
	desc, err := readExactly(r, nameAt+uint64(len(noteName)), descSize)
	if err != nil {
		damaged("read 0x%x-byte descriptor: %w", descSize, err)
		return
	}
	if !bytes.HasPrefix(desc, []byte(noteFirstKey)) {
		return
	}
	entries, err := parseNoteTable(desc)
	if err != nil {
		damaged("%w", err)
		return
	}
	scan.Tables = append(scan.Tables, VMCoreInfo{Offset: at, Entries: entries})
}

// The release is printed with %s, which stops only at NUL, so its line may
// hold any other byte but its newline; every other value is printed from a
// number or a fixed string.
func releaseLineEnd(desc []byte) int {
	if !bytes.HasPrefix(desc, []byte(noteFirstKey)) {
		return 0
	}
	end := bytes.IndexByte(desc, '\n')
	if end < 0 {
		end = len(desc)
	}
	return min(end, noteCallBytes)
}

// A backslash is doubled so that a release holding the text of an escape
// reads apart from an escaped byte.
func escapeRelease(s string) string {
	const hexDigits = "0123456789abcdef"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			out.WriteString(`\\`)
			continue
		}
		if c < 0x20 || c > 0x7e {
			out.WriteString(`\x`)
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0xf])
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

func parseNoteTable(desc []byte) ([]VMCoreInfoEntry, error) {
	release := releaseLineEnd(desc)
	for i, b := range desc {
		if i < release && b != 0 {
			continue
		}
		if (b < 0x20 || b > 0x7e) && b != '\n' {
			return nil, fmt.Errorf("byte 0x%02x at descriptor offset %d is not text", b, i)
		}
	}
	var entries []VMCoreInfoEntry
	seen := map[string]bool{}
	rest := string(desc)
	for line := 1; rest != ""; line++ {
		text, after, ended := strings.Cut(rest, "\n")
		cut := !ended
		// A call that formats 79 bytes or more keeps only its first 79 and
		// drops its newline, so the next call's text starts right after.
		if len(text) >= noteCallBytes {
			text, after, cut = rest[:noteCallBytes], rest[noteCallBytes:], true
		}
		rest = after
		if text == "" {
			return nil, fmt.Errorf("line %d is empty", line)
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("line %d has no '='", line)
		}
		e := VMCoreInfoEntry{Key: key, Text: value, Cut: cut}
		if line == 1 && release > 0 {
			e.Text = escapeRelease(value)
		}
		if format := formatOf(key); !cut && format != formatText {
			n, ok := format.parse(value)
			if !ok {
				return nil, fmt.Errorf("line %d: %s value %q is not %s", line, key, value, format)
			}
			e.Int = n
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, e)
	}
	table := VMCoreInfo{Entries: entries}
	if page, ok := table.whole("PAGESIZE"); ok && big.NewInt(int64(len(desc))).Cmp(page) > 0 {
		return nil, fmt.Errorf("0x%x-byte descriptor exceeds PAGESIZE %s", len(desc), page)
	}
	return entries, nil
}

type valueFormat int

const (
	formatText valueFormat = iota
	formatHex
	formatUnsigned
	formatSigned
	formatNumber
)

func (f valueFormat) String() string {
	switch f {
	case formatHex:
		return "64-bit lowercase hex"
	case formatUnsigned:
		return "64-bit unsigned decimal"
	case formatSigned:
		return "64-bit signed decimal"
	case formatNumber:
		return "64-bit signed decimal or 0x hex"
	}
	return "text"
}

func formatOf(key string) valueFormat {
	switch {
	case strings.HasPrefix(key, "SYMBOL("), key == "KERNELOFFSET":
		return formatHex
	case strings.HasPrefix(key, "SIZE("), strings.HasPrefix(key, "OFFSET("), strings.HasPrefix(key, "LENGTH("):
		return formatUnsigned
	case key == "PAGESIZE", key == "CRASHTIME":
		return formatSigned
	case strings.HasPrefix(key, "NUMBER("):
		return formatNumber
	}
	return formatText
}

// The kernel prints with no width or flags, so a value is accepted only as
// the exact text printf would write for it: lowercase, no '+', no leading
// zero, no "-0".
func (f valueFormat) parse(s string) (*big.Int, bool) {
	base, prefix, signed := 10, "", false
	switch f {
	case formatHex:
		base = 16
	case formatUnsigned:
	case formatSigned:
		signed = true
	case formatNumber:
		if strings.HasPrefix(s, "0x") {
			base, prefix = 16, "0x"
		} else {
			signed = true
		}
	default:
		return nil, false
	}
	n, ok := new(big.Int).SetString(s[len(prefix):], base)
	if !ok || prefix+n.Text(base) != s {
		return nil, false
	}
	if signed {
		return n, n.IsInt64()
	}
	return n, n.IsUint64()
}

type VMCoreInfoLayout struct {
	VirtualShift  uint64
	PhysBase      int64
	DTB           uint64
	FiveLevel     bool
	DepthEvidence string
	PhysAddrBits  uint
	SMEMask       uint64
}

// Kernels before v4.17 do not write NUMBER(pgtable_l5_enabled) (K10), so a
// 5-level kernel of v4.14 to v4.16 shows its depth only in its own tables.
// An undecided detection leaves the layout 4-level and is returned as the
// error, for the caller to record.
func (v VMCoreInfo) ConfirmDepth(physical memory.MemoryReader, l VMCoreInfoLayout) (VMCoreInfoLayout, error) {
	if _, ok := v.whole("NUMBER(pgtable_l5_enabled)"); ok {
		return l, nil
	}
	d, err := layers.DetectPagingMode(physical, l.DTB, 8)
	if err != nil {
		return l, fmt.Errorf("autoload: VMCOREINFO at 0x%x: no NUMBER(pgtable_l5_enabled), read as 4-level: %w", v.Offset, err)
	}
	l.FiveLevel = d.Mode.Name() == layers.ModeLA57.Name()
	l.DepthEvidence = d.Evidence
	return l, nil
}

func (v VMCoreInfo) KernelLayout() (VMCoreInfoLayout, error) {
	fail := func(format string, args ...any) (VMCoreInfoLayout, error) {
		return VMCoreInfoLayout{}, fmt.Errorf("autoload: VMCOREINFO at 0x%x: "+format, append([]any{v.Offset}, args...)...)
	}
	if e, ok := v.Lookup("CONFIG_X86_PAE"); ok && e.Text == "y" {
		return fail("describes a 32-bit kernel (PAE)")
	}
	pgd, ok := v.whole("SYMBOL(swapper_pg_dir)")
	if !ok {
		return fail("no SYMBOL(swapper_pg_dir)")
	}
	if pgd.BitLen() <= 32 {
		return fail("SYMBOL(swapper_pg_dir) 0x%x describes a 32-bit kernel", pgd)
	}
	physBase, ok := v.whole("NUMBER(phys_base)")
	if !ok || !physBase.IsInt64() {
		return fail("no signed 64-bit NUMBER(phys_base)")
	}
	offset, ok := v.whole("KERNELOFFSET")
	if !ok {
		return fail("no KERNELOFFSET")
	}

	mapping := uint64(imageMappingMax)
	if size, ok := v.whole("NUMBER(KERNEL_IMAGE_SIZE)"); ok {
		if size.Sign() <= 0 || size.Cmp(big.NewInt(imageMappingMax)) > 0 {
			return fail("NUMBER(KERNEL_IMAGE_SIZE) %s is not in 1 to 0x%x", size, imageMappingMax)
		}
		mapping = size.Uint64()
	}
	root := pgd.Uint64()
	if root < startKernelMap || root-startKernelMap >= mapping {
		return fail("SYMBOL(swapper_pg_dir) 0x%x is outside the kernel image mapping", root)
	}
	if top, ok := v.whole("SYMBOL(init_top_pgt)"); ok && top.Cmp(pgd) != 0 {
		return fail("SYMBOL(init_top_pgt) 0x%x differs from SYMBOL(swapper_pg_dir) 0x%x", top, root)
	}

	dtb := new(big.Int).SetUint64(root - startKernelMap)
	dtb.Add(dtb, physBase)
	if dtb.Sign() < 0 || dtb.BitLen() > physAddrBitsMax || dtb.Uint64()%pageTableAlign != 0 {
		return fail("page table %s from NUMBER(phys_base) %s is not a 4 KiB-aligned address below 2^52", dtb, physBase)
	}
	layout := VMCoreInfoLayout{PhysBase: physBase.Int64(), DTB: dtb.Uint64(), VirtualShift: offset.Uint64()}
	if layout.VirtualShift%kaslrAlignment != 0 || layout.VirtualShift >= mapping {
		return fail("KERNELOFFSET 0x%x is not a multiple of 0x%x below 0x%x", layout.VirtualShift, kaslrAlignment, mapping)
	}

	if n, ok := v.whole("NUMBER(pgtable_l5_enabled)"); ok {
		if !n.IsInt64() || n.Int64() != 0 && n.Int64() != 1 {
			return fail("NUMBER(pgtable_l5_enabled) %s is neither 0 nor 1", n)
		}
		layout.FiveLevel = n.Int64() == 1
	}
	if n, ok := v.whole("NUMBER(MAX_PHYSMEM_BITS)"); ok {
		if !n.IsInt64() || n.Int64() < physAddrBitsLeast || n.Int64() > physAddrBitsMax {
			return fail("NUMBER(MAX_PHYSMEM_BITS) %s is not in %d to %d", n, physAddrBitsLeast, physAddrBitsMax)
		}
		layout.PhysAddrBits = uint(n.Int64())
	}
	if n, ok := v.whole("NUMBER(sme_mask)"); ok {
		if n.Sign() < 0 || !n.IsUint64() {
			return fail("NUMBER(sme_mask) %s is negative", n)
		}
		layout.SMEMask = n.Uint64()
	}
	return layout, nil
}
