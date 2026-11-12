// NTFS keeps file record segments of the master file table in the cache and
// in pool buffers, so copies of them, live and freed, sit in physical memory.
// The three tools parse every copy found and report its timed attributes, its
// named resident data streams and its unnamed resident data (S42).
package ntfsrecord

import (
	"time"

	"github.com/aoiflux/libvapour/tools"
)

const (
	Name             = "windows.ntfs.scan_records"
	NameStreams      = "windows.ntfs.scan_streams"
	NameResidentData = "windows.ntfs.scan_resident_data"
)

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Parse NTFS file record segments found in physical memory and list their $STANDARD_INFORMATION and $FILE_NAME attributes",
		},
		RunAny,
	)
	tools.MustRegister(
		tools.Spec{
			Name:        NameStreams,
			Description: "Parse NTFS file record segments found in physical memory and list their named resident $DATA attributes",
		},
		RunStreamsAny,
	)
	tools.MustRegister(
		tools.Spec{
			Name:        NameResidentData,
			Description: "Parse NTFS file record segments found in physical memory and list their unnamed resident $DATA attributes",
		},
		RunResidentDataAny,
	)
}

const (
	typeStandardInformation = "$STANDARD_INFORMATION"
	typeFileName            = "$FILE_NAME"
)

type RecordHeader struct {
	RecordPhysical     uint64
	SegmentNumber      uint32
	SegmentNumberKnown bool
	SequenceNumber     uint16
	LinkCount          uint16
	BytesInUse         uint32
	BytesAllocated     uint32
	BaseSegmentNumber  uint64
	Flags              uint16
	InUse              bool
	NameIndexPresent   bool
	Fixup              FixupForm
}

type Row struct {
	RecordHeader
	AttributeOffset      int
	AttributeType        string
	FileAttributes       uint32
	ParentSegmentNumber  uint64
	ParentSequenceNumber uint16
	Namespace            Namespace
	Name                 string
	NameKnown            bool
	CreationTime         time.Time
	LastWriteTime        time.Time
	ChangeTime           time.Time
	LastAccessTime       time.Time
}

type StreamRow struct {
	RecordHeader
	AttributeOffset int
	Name            string
	NameKnown       bool
	StreamName      string
	Value           []byte
}

type DataRow struct {
	RecordHeader
	AttributeOffset int
	Name            string
	NameKnown       bool
	Value           []byte
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func RunStreamsAny(ctx tools.Context) (any, error) { return RunStreams(ctx) }

func RunResidentDataAny(ctx tools.Context) (any, error) { return RunResidentData(ctx) }

func header(r record) RecordHeader {
	return RecordHeader{
		RecordPhysical:     r.physical,
		SegmentNumber:      r.segment,
		SegmentNumberKnown: r.segmentKnown,
		SequenceNumber:     r.sequence,
		LinkCount:          r.linkCount,
		BytesInUse:         r.bytesInUse,
		BytesAllocated:     r.allocated,
		BaseSegmentNumber:  r.base.segment,
		Flags:              r.flags,
		InUse:              r.flags&flagInUse != 0,
		NameIndexPresent:   r.flags&flagNameIndexPresent != 0,
		Fixup:              r.fixup,
	}
}

type timedAttribute struct {
	offset   int
	standard *standardInformation
	name     *fileName
}

type readRecord struct {
	record
	timed []timedAttribute
	names []fileName
}

func read(r record, bad *tally) readRecord {
	out := readRecord{record: r}
	for _, a := range r.attributes {
		switch a.typeCode {
		case codeStandardInformation:
			si, err := a.standardInformation()
			if err != nil {
				bad.add(err, r.physical)
				continue
			}
			out.timed = append(out.timed, timedAttribute{offset: a.offset, standard: &si})
		case codeFileName:
			fn, err := a.fileName()
			if err != nil {
				bad.add(err, r.physical)
				continue
			}
			out.timed = append(out.timed, timedAttribute{offset: a.offset, name: &fn})
			out.names = append(out.names, fn)
		}
	}
	return out
}

func readAll(ctx tools.Context, tool string) ([]readRecord, error) {
	records, err := scan(ctx, tool)
	var bad tally
	out := make([]readRecord, len(records))
	for i, r := range records {
		out[i] = read(r, &bad)
	}
	for _, e := range bad.order {
		ctx.AddDiagnostic("%s: %d attributes not read, first in the record at 0x%x: %v", tool, bad.count[e],
			bad.first[e], e)
	}
	return out, err
}

func timedRows(r readRecord) []Row {
	h := header(r.record)
	name, known := preferredName(r.names)
	rows := make([]Row, 0, len(r.timed))
	for _, t := range r.timed {
		row := Row{RecordHeader: h, AttributeOffset: t.offset}
		var ts times
		if t.standard != nil {
			row.AttributeType, row.FileAttributes, row.Name, row.NameKnown = typeStandardInformation,
				t.standard.fileAttributes, name, known
			ts = t.standard.times
		} else {
			row.AttributeType, row.Name, row.NameKnown = typeFileName, t.name.name, true
			row.ParentSegmentNumber, row.ParentSequenceNumber = t.name.parent.segment, t.name.parent.sequence
			row.Namespace = t.name.namespace
			ts = t.name.times
		}
		row.CreationTime, row.LastWriteTime, row.ChangeTime, row.LastAccessTime = ts.creation, ts.lastWrite,
			ts.change, ts.lastAccess
		rows = append(rows, row)
	}
	return rows
}

func Run(ctx tools.Context) ([]Row, error) {
	records, err := readAll(ctx, Name)
	var out []Row
	for _, r := range records {
		out = append(out, timedRows(r)...)
	}
	return out, err
}

func residentData(r readRecord) []attribute {
	var out []attribute
	for _, a := range r.attributes {
		if a.typeCode == codeData && a.resident {
			out = append(out, a)
		}
	}
	return out
}

func RunStreams(ctx tools.Context) ([]StreamRow, error) {
	records, err := readAll(ctx, NameStreams)
	var out []StreamRow
	for _, r := range records {
		name, known := preferredName(r.names)
		for _, a := range residentData(r) {
			if a.name == "" {
				continue
			}
			out = append(out, StreamRow{RecordHeader: header(r.record), AttributeOffset: a.offset, Name: name,
				NameKnown: known, StreamName: a.name, Value: a.value})
		}
	}
	return out, err
}

func RunResidentData(ctx tools.Context) ([]DataRow, error) {
	records, err := readAll(ctx, NameResidentData)
	var out []DataRow
	for _, r := range records {
		name, known := preferredName(r.names)
		for _, a := range residentData(r) {
			if a.name != "" {
				continue
			}
			out = append(out, DataRow{RecordHeader: header(r.record), AttributeOffset: a.offset, Name: name,
				NameKnown: known, Value: a.value})
		}
	}
	return out, err
}
