package registryhive

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/aoiflux/libvapour/symbols"
)

var ErrLayout = errors.New("registryhive: registry types unusable in the symbol table")

const (
	hiveSignature = 0xbee0bee0
	baseSignature = 0x66676572
	binFlagMask   = 0xf
)

// The cell index splits into storage, directory slot, table slot and offset
// in the block; the widths come from the array lengths of the map types.
type cellIndexShape struct {
	storageCount uint64
	dirSlots     uint64
	tableSlots   uint64
	blockSize    uint64
	blockBits    uint
	tableBits    uint
}

func (s cellIndexShape) split(index uint32) (storage, dir, table, offset uint64) {
	storage = uint64(index >> 31)
	rest := uint64(index & 0x7fffffff)
	offset = rest & (s.blockSize - 1)
	table = (rest >> s.blockBits) & (s.tableSlots - 1)
	dir = rest >> (s.blockBits + s.tableBits)
	return
}

type keyCellLayout struct {
	signature, flags, lastWrite, parent uint64
	subkeyCounts, subkeyLists           uint64
	valueCount, valueList               uint64
	class, nameLength, classLength      uint64
	hasParent, hasClass                 bool
	name                                uint64
}

type valueCellLayout struct {
	signature, nameLength, dataLength, data, typ, flags, name uint64
}

type indexCellLayout struct {
	signature, count, list uint64
	leafStride, leafCell   uint64
}

type bigDataLayout struct {
	signature, count, list uint64
}

type binLayout struct {
	signature, fileOffset, headerSize uint64
}

type layout struct {
	width uint64

	hive                                   uint64
	hiveList, fullPath, userName, rootPath uint64
	hasUserName, hasRootPath               bool
	hasHiveList, hasFullPath               bool
	rootKcb, kcbKeyCell                    uint64
	hasRootKcb                             bool

	signature, baseBlock, storage, dualSize uint64
	dualLength, dualMap                     uint64
	entrySize, entryBlockOffset, entryBin   uint64
	shape                                   cellIndexShape

	baseSig, baseRoot uint64

	bin    binLayout
	key    keyCellLayout
	value  valueCellLayout
	index  indexCellLayout
	big    bigDataLayout
	hasBig bool
}

type typeReader struct {
	table symbols.SymbolTable
	errs  []error
}

func (r *typeReader) field(t, f string) symbols.Field {
	fl, err := r.table.Field(t, f)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s.%s: %w", t, f, err))
	}
	return fl
}

func (r *typeReader) offset(t, f string) uint64 { return r.field(t, f).Offset }

func (r *typeReader) size(t string) uint64 {
	st, err := r.table.Struct(t)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s: %w", t, err))
		return 0
	}
	if st.Size == 0 {
		r.errs = append(r.errs, fmt.Errorf("%s: size 0", t))
	}
	return st.Size
}

// Members a reader can do without: paths, the parent check, class data and
// big-data values are then left out.
func optional(table symbols.SymbolTable, t, f string) (uint64, bool) {
	fl, err := table.Field(t, f)
	if err != nil {
		return 0, false
	}
	return fl.Offset, true
}

func arrayLength(f symbols.Field) uint64 {
	if f.Type.ArrayLength > 0 {
		return f.Type.ArrayLength
	}
	if f.Type.Element != nil {
		return f.Type.Element.ArrayLength
	}
	return 0
}

func loadLayout(table symbols.SymbolTable) (*layout, error) {
	if table == nil {
		return nil, fmt.Errorf("%w: no symbol table", ErrLayout)
	}
	r := &typeReader{table: table}
	l := &layout{width: uint64(table.PointerSize())}
	if l.width != 4 && l.width != 8 {
		return nil, fmt.Errorf("%w: pointer size %d", ErrLayout, l.width)
	}

	// Hive is at +0 on every build measured; the list members are needed
	// only to walk the hive list.
	l.hive, _ = optional(table, "_CMHIVE", "Hive")
	l.hiveList, l.hasHiveList = optional(table, "_CMHIVE", "HiveList")
	l.fullPath, l.hasFullPath = optional(table, "_CMHIVE", "FileFullPath")
	l.userName, l.hasUserName = optional(table, "_CMHIVE", "FileUserName")
	l.rootPath, l.hasRootPath = optional(table, "_CMHIVE", "HiveRootPath")
	if kcb, err := table.Field("_CMHIVE", "RootKcb"); err == nil {
		if cell, err := table.Field("_CM_KEY_CONTROL_BLOCK", "KeyCell"); err == nil {
			l.rootKcb, l.kcbKeyCell, l.hasRootKcb = kcb.Offset, cell.Offset, true
		}
	}

	l.signature = r.offset("_HHIVE", "Signature")
	l.baseBlock = r.offset("_HHIVE", "BaseBlock")
	storage := r.field("_HHIVE", "Storage")
	l.storage = storage.Offset
	l.dualSize = r.size("_DUAL")
	l.dualLength = r.offset("_DUAL", "Length")
	l.dualMap = r.offset("_DUAL", "Map")
	l.entrySize = r.size("_HMAP_ENTRY")
	l.entryBlockOffset = r.offset("_HMAP_ENTRY", "BlockOffset")
	l.entryBin = r.offset("_HMAP_ENTRY", "PermanentBinAddress")
	l.shape = cellIndexShape{
		storageCount: arrayLength(storage),
		dirSlots:     arrayLength(r.field("_HMAP_DIRECTORY", "Directory")),
		tableSlots:   arrayLength(r.field("_HMAP_TABLE", "Table")),
		blockSize:    r.size("_HBASE_BLOCK"),
	}

	l.baseSig = r.offset("_HBASE_BLOCK", "Signature")
	l.baseRoot = r.offset("_HBASE_BLOCK", "RootCell")

	// 26100 tables carry no _HBIN; the members measured there sit where the
	// 19041 and 14393 type puts them.
	l.bin = binLayout{signature: 0, fileOffset: 4, headerSize: 0x20}
	if st, err := table.Struct("_HBIN"); err == nil && st.Size > 0 {
		sig, e1 := table.Field("_HBIN", "Signature")
		off, e2 := table.Field("_HBIN", "FileOffset")
		if e1 == nil && e2 == nil {
			l.bin = binLayout{signature: sig.Offset, fileOffset: off.Offset, headerSize: st.Size}
		}
	}

	values := r.offset("_CM_KEY_NODE", "ValueList")
	l.key = keyCellLayout{
		signature:    r.offset("_CM_KEY_NODE", "Signature"),
		flags:        r.offset("_CM_KEY_NODE", "Flags"),
		lastWrite:    r.offset("_CM_KEY_NODE", "LastWriteTime"),
		subkeyCounts: r.offset("_CM_KEY_NODE", "SubKeyCounts"),
		subkeyLists:  r.offset("_CM_KEY_NODE", "SubKeyLists"),
		valueCount:   values + r.offset("_CHILD_LIST", "Count"),
		valueList:    values + r.offset("_CHILD_LIST", "List"),
		nameLength:   r.offset("_CM_KEY_NODE", "NameLength"),
		name:         r.offset("_CM_KEY_NODE", "Name"),
	}
	l.key.parent, l.key.hasParent = optional(table, "_CM_KEY_NODE", "Parent")
	l.key.class, l.key.hasClass = optional(table, "_CM_KEY_NODE", "Class")
	if cl, ok := optional(table, "_CM_KEY_NODE", "ClassLength"); ok {
		l.key.classLength = cl
	} else {
		l.key.hasClass = false
	}
	l.value = valueCellLayout{
		signature:  r.offset("_CM_KEY_VALUE", "Signature"),
		nameLength: r.offset("_CM_KEY_VALUE", "NameLength"),
		dataLength: r.offset("_CM_KEY_VALUE", "DataLength"),
		data:       r.offset("_CM_KEY_VALUE", "Data"),
		typ:        r.offset("_CM_KEY_VALUE", "Type"),
		flags:      r.offset("_CM_KEY_VALUE", "Flags"),
		name:       r.offset("_CM_KEY_VALUE", "Name"),
	}
	l.index = indexCellLayout{
		signature:  r.offset("_CM_KEY_INDEX", "Signature"),
		count:      r.offset("_CM_KEY_INDEX", "Count"),
		list:       r.offset("_CM_KEY_INDEX", "List"),
		leafStride: r.size("_CM_INDEX"),
		leafCell:   r.offset("_CM_INDEX", "Cell"),
	}
	if sig, ok := optional(table, "_CM_BIG_DATA", "Signature"); ok {
		count, ok1 := optional(table, "_CM_BIG_DATA", "Count")
		list, ok2 := optional(table, "_CM_BIG_DATA", "List")
		l.big, l.hasBig = bigDataLayout{signature: sig, count: count, list: list}, ok1 && ok2
	}

	if len(r.errs) > 0 {
		return nil, fmt.Errorf("%w: %w", ErrLayout, errors.Join(r.errs...))
	}
	if err := l.shape.check(); err != nil {
		return nil, err
	}
	return l, nil
}

func (s *cellIndexShape) check() error {
	for _, n := range []uint64{s.storageCount, s.dirSlots, s.tableSlots, s.blockSize} {
		if n == 0 || n&(n-1) != 0 {
			return fmt.Errorf("%w: map shape %d storages, %d directory slots, %d table slots, %d-byte blocks is not made of powers of two",
				ErrLayout, s.storageCount, s.dirSlots, s.tableSlots, s.blockSize)
		}
	}
	s.blockBits = uint(bits.TrailingZeros64(s.blockSize))
	s.tableBits = uint(bits.TrailingZeros64(s.tableSlots))
	dirBits := uint(bits.TrailingZeros64(s.dirSlots))
	storageBits := uint(bits.TrailingZeros64(s.storageCount))
	if storageBits != 1 || storageBits+dirBits+s.tableBits+s.blockBits != 32 {
		return fmt.Errorf("%w: map shape of %d storages, %d directory slots, %d table slots and %d-byte blocks does not fill a 32-bit cell index",
			ErrLayout, s.storageCount, s.dirSlots, s.tableSlots, s.blockSize)
	}
	return nil
}
