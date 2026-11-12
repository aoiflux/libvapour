package peversion

import (
	"bytes"
	"encoding/binary"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/aoiflux/libvapour/memory"
	"github.com/aoiflux/libvapour/pe"
	"github.com/aoiflux/libvapour/tools"
)

// A kernel module's resource pages are often not mapped, while the file's
// pages, version resource included, stay in physical memory as file cache.
// A VS_VERSIONINFO there is tied to a module only through the
// OriginalFilename string of its StringFileInfo.
func fillFromPhysical(ctx tools.Context, rows []Version, paths []string) {
	want := map[string][]int{}
	asked := 0
	for i, r := range rows {
		if !r.VersionUnreadable || r.NameUnreadable {
			continue
		}
		asked++
		for _, n := range fileNames(r.Name, paths[i]) {
			want[n] = append(want[n], i)
		}
	}
	if asked == 0 {
		return
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		ctx.AddDiagnostic("%s: %s set but there is no physical memory: %d kernel modules not searched", Name, OptionExtensive, asked)
		return
	}
	copies := map[string]cachedVersion{}
	differing := map[string]bool{}
	scanPhysical(phys, versionKeyBytes, func(keyAt uint64) {
		if keyAt < nodeHeaderBytes {
			return
		}
		at := keyAt - nodeHeaderBytes
		c, ok := readCachedVersion(phys, at)
		if !ok {
			return
		}
		name := strings.ToLower(c.name)
		if _, wanted := want[name]; !wanted {
			return
		}
		if first, seen := copies[name]; !seen {
			copies[name] = c
		} else if first.info.ProductVersion() != c.info.ProductVersion() {
			differing[name] = true
		}
	})
	filled := 0
	for name, idx := range want {
		c, ok := copies[name]
		if !ok {
			continue
		}
		for _, i := range idx {
			if rows[i].VersionUnreadable {
				setProductVersion(&rows[i], c.info)
				rows[i].VersionPhysical = c.at
				filled++
			}
		}
	}
	ctx.AddDiagnostic("%s: %d of %d kernel modules without a mapped version resource matched a cached copy in physical memory",
		Name, filled, asked)
	for _, name := range slices.Sorted(maps.Keys(differing)) {
		ctx.AddDiagnostic("%s: cached version resources naming %s hold different product versions: the lowest physical address is used",
			Name, name)
	}
}

func fileNames(name, path string) []string {
	out := []string{strings.ToLower(name)}
	if p := strings.ToLower(path[strings.LastIndexAny(path, `\/`)+1:]); p != "" && p != out[0] {
		out = append(out, p)
	}
	return out
}

type cachedVersion struct {
	at   uint64
	name string
	info pe.FixedFileInfo
}

var versionKeyBytes = utf16LE(versionInfoKey + "\x00")

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

func readCachedVersion(phys memory.MemoryReader, at uint64) (cachedVersion, bool) {
	head, err := phys.ReadAt(at, 2)
	if err != nil || len(head) != 2 {
		return cachedVersion{}, false
	}
	length := uint64(binary.LittleEndian.Uint16(head))
	if length < nodeHeaderBytes {
		return cachedVersion{}, false
	}
	data, err := phys.ReadAt(at, length)
	if err != nil || uint64(len(data)) != length {
		return cachedVersion{}, false
	}
	info, err := pe.ParseVersionInfo(data, uint32(at))
	if err != nil {
		return cachedVersion{}, false
	}
	name, ok := originalFilename(data, at)
	if !ok || name == "" {
		return cachedVersion{}, false
	}
	return cachedVersion{at: at, name: name, info: info}, true
}

const scanChunkBytes = 4 << 20

// scanPhysical calls found with the address of each match, in address
// order. A chunk that does not read whole is read page by page; a match
// across two readable neighbours is found, one across a hole is not.
func scanPhysical(r memory.MemoryReader, needle []byte, found func(uint64)) {
	var tail []byte
	var tailEnd uint64
	feed := func(at uint64, data []byte) {
		if len(tail) > 0 && tailEnd == at {
			edge := append(append([]byte(nil), tail...), data[:min(len(data), len(needle)-1)]...)
			start := at - uint64(len(tail))
			for i := 0; ; {
				j := bytes.Index(edge[i:], needle)
				if j < 0 || i+j >= len(tail) {
					break
				}
				found(start + uint64(i+j))
				i += j + 1
			}
		}
		for i := 0; ; {
			j := bytes.Index(data[i:], needle)
			if j < 0 {
				break
			}
			found(at + uint64(i+j))
			i += j + 1
		}
		keep := min(len(needle)-1, len(data))
		tail = append(tail[:0], data[len(data)-keep:]...)
		tailEnd = at + uint64(len(data))
	}
	size := r.Size()
	for off := uint64(0); off < size; off += scanChunkBytes {
		n := min(uint64(scanChunkBytes), size-off)
		if b, err := r.ReadAt(off, n); err == nil && uint64(len(b)) == n {
			feed(off, b)
			continue
		}
		for page := off; page < off+n; page += tools.PageSize {
			pn := min(tools.PageSize, off+n-page)
			if b, err := r.ReadAt(page, pn); err == nil && uint64(len(b)) == pn {
				feed(page, b)
			}
		}
	}
}
