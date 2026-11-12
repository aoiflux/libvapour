package logkernel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/limits"
	lt "github.com/aoiflux/libvapour/symbols/linuxkernel/linuxtest"
	"github.com/aoiflux/libvapour/tools"
	. "github.com/aoiflux/libvapour/tools/linuxkern/kerntest"
)

const (
	prbSym   = 0xffffffff83000000
	ringAt   = 0xffffffff83000100
	descsAt  = 0xffffffff84000000
	infosAt  = 0xffffffff84100000
	dataAt   = 0xffffffff84200000
	descSize = 24
	infoSize = 88
	stateTop = 62
	mask48   = 1<<48 - 1
)

// Fixture state codes: the zero value is the common case, a finalized record.
const (
	fxFinalized = iota
	fxCommitted
	fxReserved
	fxReusable
)

var kernelState = map[int]uint64{fxFinalized: 2, fxCommitted: 1, fxReserved: 0, fxReusable: 3}

func fld(off uint64, t T) F { return F{Off: off, Type: t} }

func ringTypes(i *Types) {
	i.Struct("atomic64_t", 8, map[string]F{"counter": fld(0, Base("long long int"))})
	i.Struct("printk_ringbuffer", 88, map[string]F{
		"desc_ring": fld(0, Struct("prb_desc_ring")), "text_data_ring": fld(48, Struct("prb_data_ring")),
		"fail": fld(80, Struct("atomic64_t")),
	})
	i.Struct("prb_desc_ring", 48, map[string]F{
		"count_bits": fld(0, Base("unsigned int")), "descs": fld(8, Ptr(Struct("prb_desc"))),
		"infos": fld(16, Ptr(Struct("printk_info"))), "head_id": fld(24, Struct("atomic64_t")),
		"tail_id": fld(32, Struct("atomic64_t")), "last_finalized_seq": fld(40, Struct("atomic64_t")),
	})
	i.Struct("prb_data_ring", 32, map[string]F{
		"size_bits": fld(0, Base("unsigned int")), "data": fld(8, Ptr(Base("char"))),
		"head_lpos": fld(16, Struct("atomic64_t")), "tail_lpos": fld(24, Struct("atomic64_t")),
	})
	i.Struct("prb_data_blk_lpos", 16, map[string]F{
		"begin": fld(0, Base("long unsigned int")), "next": fld(8, Base("long unsigned int")),
	})
	i.Struct("prb_desc", descSize, map[string]F{
		"state_var": fld(0, Struct("atomic64_t")), "text_blk_lpos": fld(8, Struct("prb_data_blk_lpos")),
	})
	i.Struct("dev_printk_info", 64, map[string]F{
		"subsystem": fld(0, Arr(16, Base("char"))), "device": fld(16, Arr(48, Base("char"))),
	})
	i.Struct("printk_info", infoSize, map[string]F{
		"seq": fld(0, Base("long long unsigned int")), "ts_nsec": fld(8, Base("long long unsigned int")),
		"text_len": fld(16, Base("short unsigned int")), "facility": fld(18, Base("unsigned char")),
		"flags": fld(19, Bits(0, 5, "unsigned char")), "level": fld(19, Bits(5, 3, "unsigned char")),
		"caller_id": fld(20, Base("unsigned int")), "dev_info": fld(24, Struct("dev_printk_info")),
	})
}

type ringFix struct {
	types     *Types
	mem       *Memory
	countBits uint64
	sizeBits  uint64
	headID    uint64
	tailID    uint64
	headLpos  uint64
	tailLpos  uint64
	seq       uint64
	opts      map[string]any
	lim       limits.Limits
}

type rec struct {
	text      string
	state     int
	ts        uint64
	facility  uint8
	level     uint8
	flags     uint8
	caller    uint32
	subsystem string
	device    string
	emptyLine bool
}

const idMask64 = 1<<62 - 1

func desc0ID(countBits uint64) uint64 { return uint64(-uint32(1<<countBits+1)) & idMask64 }

// newRing lays out a ring as prb_init leaves it, with the data head and tail
// placed start bytes into the array so a test can make the next block wrap.
func newRing(countBits, sizeBits, start uint64) *ringFix {
	f := &ringFix{types: NewTypes(8), mem: NewMemory(), countBits: countBits, sizeBits: sizeBits}
	ringTypes(f.types)
	f.types.Symbol("prb", prbSym, Ptr(Struct("printk_ringbuffer")))
	f.headID, f.tailID = desc0ID(countBits), desc0ID(countBits)
	f.headLpos = -(uint64(1) << sizeBits) + start
	f.tailLpos = f.headLpos
	count := uint64(1) << countBits
	f.mem.Map(descsAt, count*descSize)
	f.mem.Map(infosAt, count*infoSize)
	f.mem.Map(dataAt, 1<<sizeBits)
	last := descsAt + (count-1)*descSize
	f.mem.U64(last, kernelState[fxReusable]<<stateTop|f.tailID)
	f.mem.U64(last+8, lposFailed)
	f.mem.U64(last+16, lposFailed)
	f.mem.U64(infosAt, -count)
	f.header()
	return f
}

func (f *ringFix) header() {
	f.mem.U64(prbSym, ringAt)
	f.mem.U32(ringAt, uint32(f.countBits))
	f.mem.U64(ringAt+8, descsAt)
	f.mem.U64(ringAt+16, infosAt)
	f.mem.U64(ringAt+24, f.headID)
	f.mem.U64(ringAt+32, f.tailID)
	f.mem.U32(ringAt+48, uint32(f.sizeBits))
	f.mem.U64(ringAt+56, dataAt)
	f.mem.U64(ringAt+64, f.headLpos)
	f.mem.U64(ringAt+72, f.tailLpos)
}

func (f *ringFix) descAt(id uint64) uint64 { return descsAt + (id&(1<<f.countBits-1))*descSize }

func (f *ringFix) infoAt(id uint64) uint64 { return infosAt + (id&(1<<f.countBits-1))*infoSize }

// add stores a record the way prb_reserve and get_next_lpos place it, and
// returns its id.
func (f *ringFix) add(r rec) uint64 {
	id := (f.headID + 1) & idMask64
	size := uint64(1) << f.sizeBits
	begin, next := uint64(lposEmptyLine), uint64(lposEmptyLine)
	if !r.emptyLine {
		blk := (8 + uint64(len(r.text)) + 7) &^ 7
		begin, next = f.headLpos, f.headLpos+blk
		at := begin & (size - 1)
		if begin>>f.sizeBits != next>>f.sizeBits {
			f.mem.U64(dataAt+at, id)
			next = next&^(size-1) + blk
			at = 0
		}
		f.mem.U64(dataAt+at, id)
		f.mem.Write(dataAt+at+8, []byte(r.text))
		f.headLpos = next
	}
	d := f.descAt(id)
	f.mem.U64(d, kernelState[r.state]<<stateTop|id)
	f.mem.U64(d+8, begin)
	f.mem.U64(d+16, next)
	in := f.infoAt(id)
	f.mem.U64(in, f.seq)
	f.mem.U64(in+8, r.ts)
	f.mem.U16(in+16, uint16(len(r.text)))
	f.mem.U8(in+18, r.facility)
	f.mem.U8(in+19, r.flags|r.level<<5)
	f.mem.U32(in+20, r.caller)
	f.mem.Write(in+24, append([]byte(r.subsystem), 0))
	f.mem.Write(in+40, append([]byte(r.device), 0))
	f.seq++
	f.headID = id
	f.header()
	return id
}

func (f *ringFix) run(t *testing.T) ([]Row, []string, error) {
	t.Helper()
	ctx, diags := Context(f.mem, f.types.Table(t), f.opts)
	ctx.Limits = f.lim
	rows, err := Run(ctx)
	return rows, *diags, err
}

func lines(rows []Row) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Line)
	}
	return strings.Join(out, "|")
}

// vmcoreinfoNote gives the ring layout in VMCOREINFO's words, as
// log_buf_vmcoreinfo_setup writes it.
func vmcoreinfoNote() *lt.Memory {
	keys := []string{"OSRELEASE=6.17.0",
		"SIZE(printk_ringbuffer)=88", "OFFSET(printk_ringbuffer.desc_ring)=0", "OFFSET(printk_ringbuffer.text_data_ring)=48",
		"SIZE(prb_desc_ring)=48", "OFFSET(prb_desc_ring.count_bits)=0", "OFFSET(prb_desc_ring.descs)=8",
		"OFFSET(prb_desc_ring.infos)=16", "OFFSET(prb_desc_ring.head_id)=24", "OFFSET(prb_desc_ring.tail_id)=32",
		"SIZE(prb_desc)=24", "OFFSET(prb_desc.state_var)=0", "OFFSET(prb_desc.text_blk_lpos)=8",
		"SIZE(prb_data_blk_lpos)=16", "OFFSET(prb_data_blk_lpos.begin)=0", "OFFSET(prb_data_blk_lpos.next)=8",
		"SIZE(printk_info)=88", "OFFSET(printk_info.seq)=0", "OFFSET(printk_info.ts_nsec)=8",
		"OFFSET(printk_info.text_len)=16", "OFFSET(printk_info.caller_id)=20", "OFFSET(printk_info.dev_info)=24",
		"SIZE(dev_printk_info)=64", "OFFSET(dev_printk_info.subsystem)=0", "LENGTH(printk_info_subsystem)=16",
		"OFFSET(dev_printk_info.device)=16", "LENGTH(printk_info_device)=48",
		"SIZE(prb_data_ring)=32", "OFFSET(prb_data_ring.size_bits)=0", "OFFSET(prb_data_ring.data)=8",
		"OFFSET(prb_data_ring.head_lpos)=16", "OFFSET(prb_data_ring.tail_lpos)=24"}
	buf := make([]byte, 0x4000)
	lt.PutNote(buf, 0x1000, strings.Join(keys, "\n")+"\n")
	return &lt.Memory{Buf: buf}
}

func withPhysical(opts map[string]any, phys *lt.Memory) map[string]any {
	out := map[string]any{tools.OptionPhysicalMemory: phys}
	for k, v := range opts {
		out[k] = v
	}
	return out
}

func describe(r Row) string { return fmt.Sprintf("%+v", r) }
