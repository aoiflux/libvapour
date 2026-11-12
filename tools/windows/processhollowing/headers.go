package processhollowing

import (
	"bytes"
	"fmt"

	"github.com/aoiflux/libvapour/pe"
)

type headerField struct {
	name string
	get  func(*pe.Headers) uint64
}

var headerFields = []headerField{
	{"Machine", func(h *pe.Headers) uint64 { return uint64(h.File.Machine) }},
	{"NumberOfSections", func(h *pe.Headers) uint64 { return uint64(h.File.NumberOfSections) }},
	{"TimeDateStamp", func(h *pe.Headers) uint64 { return uint64(h.File.TimeDateStamp) }},
	{"SizeOfOptionalHeader", func(h *pe.Headers) uint64 { return uint64(h.File.SizeOfOptionalHeader) }},
	{"Characteristics", func(h *pe.Headers) uint64 { return uint64(h.File.Characteristics) }},
	{"Magic", func(h *pe.Headers) uint64 { return uint64(h.Optional.Magic) }},
	{"AddressOfEntryPoint", func(h *pe.Headers) uint64 { return uint64(h.Optional.AddressOfEntryPoint) }},
	{"ImageBase", func(h *pe.Headers) uint64 { return h.Optional.ImageBase }},
	{"SectionAlignment", func(h *pe.Headers) uint64 { return uint64(h.Optional.SectionAlignment) }},
	{"FileAlignment", func(h *pe.Headers) uint64 { return uint64(h.Optional.FileAlignment) }},
	{"SizeOfImage", func(h *pe.Headers) uint64 { return uint64(h.Optional.SizeOfImage) }},
	{"SizeOfHeaders", func(h *pe.Headers) uint64 { return uint64(h.Optional.SizeOfHeaders) }},
	{"CheckSum", func(h *pe.Headers) uint64 { return uint64(h.Optional.CheckSum) }},
}

// The mapped header page is compared with the page at file offset 0 of the
// image section the view maps. Only the bytes through the section table are
// compared: past it the memory manager zero-fills the mapped page.
func headerDifferences(mapped, file []byte) ([]string, error) {
	m, err := pe.ParseHeaders(mapped)
	if err != nil {
		return nil, fmt.Errorf("mapped: %w", err)
	}
	span := min(m.HeaderSpan(), uint64(len(mapped)), uint64(len(file)))
	if bytes.Equal(mapped[:span], file[:span]) {
		return nil, nil
	}
	f, err := pe.ParseHeaders(file)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, hf := range headerFields {
		if a, b := hf.get(m), hf.get(f); a != b {
			out = append(out, fmt.Sprintf("%s 0x%x, section 0x%x", hf.name, a, b))
		}
	}
	for i := range min(len(m.Sections), len(f.Sections)) {
		a, b := m.Sections[i], f.Sections[i]
		if a.Name != b.Name || a.VirtualAddress != b.VirtualAddress || a.VirtualSize != b.VirtualSize ||
			a.SizeOfRawData != b.SizeOfRawData || a.PointerToRawData != b.PointerToRawData ||
			a.Characteristics != b.Characteristics {
			out = append(out, fmt.Sprintf("section header %d", i))
		}
	}
	if len(out) == 0 {
		out = append(out, fmt.Sprintf("other bytes below 0x%x", span))
	}
	return out, nil
}
