package diskbootrecords

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/tools"
)

const Name = "windows.disk.scan_boot_records"

const OptionFull = "windows.disk.scan_boot_records.full"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Scan physical memory for master boot records: disk signature, boot code hash and listing, and the partition table entries",
		},
		RunAny,
	)
}

var (
	ErrNoPhysicalMemory = errors.New("diskbootrecords: no physical memory layer")
	ErrUnreadMemory     = errors.New("diskbootrecords: physical memory did not read whole")
)

type Row struct {
	Depth  int
	Offset uint64

	DiskSignature string
	BootcodeMD5   string
	FullMBRMD5    string
	ValidTable    bool
	TableProblem  string
	Disasm        string
	Bootcode      []byte

	PartitionIndex   int
	Bootable         bool
	BootFlag         uint8
	PartitionType    string
	PartitionTypeRaw uint8
	RelativeSectors  uint32
	TotalSectors     uint32
	StartingCylinder uint16
	StartingHead     uint8
	StartingSector   uint8
	EndingCylinder   uint16
	EndingHead       uint8
	EndingSector     uint8
}

// Names from the System ID table of Microsoft Learn (S66 BD5); other values
// keep only their number.
var systemIDNames = map[uint8]string{
	0x01: "FAT12",
	0x04: "FAT16",
	0x05: "Extended",
	0x06: "FAT16 (BIGDOS)",
	0x07: "Installable File System (NTFS)",
	0x0B: "FAT32",
	0x0C: "FAT32 (INT 13h extensions)",
	0x0E: "FAT16 (BIGDOS, INT 13h extensions)",
	0x0F: "Extended (INT 13h extensions)",
	0x12: "EISA or OEM",
	0x42: "Dynamic volume",
	0x84: "Hibernation (power management)",
	0x86: "Multidisk FAT16 (Windows NT 4.0)",
	0x87: "Multidisk NTFS (Windows NT 4.0)",
	0xA0: "Hibernation (laptop)",
	0xDE: "Dell OEM",
	0xFE: "IBM OEM",
	0xEE: "GPT protective",
	0xEF: "EFI System",
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	full, err := ctx.BoolOption(OptionFull)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	phys := ctx.PhysicalMemory()
	if phys == nil {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoPhysicalMemory)
	}
	l := ctx.Bounds()
	var rows []Row
	var st scanStats
	records, invalid, cut, capped := 0, 0, 0, false
	scan(phys, &st, func(addr uint64, b []byte) bool {
		rec, ok := parseRecord(b)
		if !ok {
			return true
		}
		problem := rec.tableProblem()
		if problem != "" {
			invalid++
			if !full {
				return true
			}
		}
		if records == l.MaxRowsPerObject {
			capped = true
			return false
		}
		records++
		head, listed := recordRow(rec, addr, problem, l.MaxTextBytes)
		if !listed {
			cut++
		}
		rows = append(rows, head)
		for _, e := range rec.entries {
			if e.inUse() {
				rows = append(rows, entryRow(e, addr))
			}
		}
		return true
	})
	report(ctx, st, invalid, cut, capped, full, l.MaxRowsPerObject, l.MaxTextBytes)
	if st.unreadPages > 0 && ctx.StrictMode() {
		return rows, fmt.Errorf("%s: strict mode: %w: %d pages, the first at 0x%x: %v", Name, ErrUnreadMemory,
			st.unreadPages, st.firstUnread, st.unreadErr)
	}
	return rows, nil
}

func recordRow(rec record, addr uint64, problem string, maxText int64) (Row, bool) {
	code := rec.bootCode()
	sumCode, sumAll := md5.Sum(code), md5.Sum(rec.bytes[:])
	listing, whole := listBootCode(code, maxText)
	return Row{
		Offset:        addr,
		DiskSignature: fmt.Sprintf("%08x", rec.diskSignature()),
		BootcodeMD5:   hex.EncodeToString(sumCode[:]),
		FullMBRMD5:    hex.EncodeToString(sumAll[:]),
		ValidTable:    problem == "",
		TableProblem:  problem,
		Disasm:        listing,
		Bootcode:      append([]byte(nil), code...),
	}, whole
}

func entryRow(e entry, addr uint64) Row {
	return Row{
		Depth:            1,
		Offset:           addr,
		PartitionIndex:   e.index,
		Bootable:         e.indicator == indicatorActive,
		BootFlag:         e.indicator,
		PartitionType:    systemIDNames[e.systemID],
		PartitionTypeRaw: e.systemID,
		RelativeSectors:  e.relative,
		TotalSectors:     e.total,
		StartingCylinder: e.startCylinder,
		StartingHead:     e.startHead,
		StartingSector:   e.startSector,
		EndingCylinder:   e.endCylinder,
		EndingHead:       e.endHead,
		EndingSector:     e.endSector,
	}
}

func report(ctx tools.Context, st scanStats, invalid, cut int, capped, full bool, maxRows int, maxText int64) {
	if st.unreadPages > 0 {
		ctx.AddDiagnostic("%s: physical memory at 0x%x: %d pages did not read and were not scanned: %v", Name,
			st.firstUnread, st.unreadPages, st.unreadErr)
	}
	if st.torn > 0 {
		ctx.AddDiagnostic("%s: %d records end in 0x55AA but lie partly on pages that did not read: not decoded", Name, st.torn)
	}
	if invalid > 0 && !full {
		ctx.AddDiagnostic("%s: %d records end in 0x55AA but their partition table breaks a rule: listed only with %s", Name,
			invalid, OptionFull)
	}
	if cut > 0 {
		ctx.AddDiagnostic("%s: %d boot code listings cut at %d bytes", Name, cut, maxText)
	}
	if capped {
		ctx.AddDiagnostic("%s: stopped at %d records (MaxRowsPerObject); the rest of physical memory was not scanned", Name, maxRows)
	}
}
