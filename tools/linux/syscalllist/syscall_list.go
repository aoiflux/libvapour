package syscalllist

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxkern"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
)

const Name = "linux.syscall.list"

func init() {
	tools.MustRegister(
		tools.Spec{Name: Name, Description: "List each Linux system call table entry and the module and symbol its handler lies in"},
		RunAny,
	)
}

type Row struct {
	TableAddress   uint64
	TableName      string
	Index          uint64
	HandlerAddress uint64
	HandlerSymbol  string
	Module         string
	Dispatches     bool
}

var (
	ErrNoTable = errors.New("syscalllist: no sys_call_table symbol")
	ErrNoSize  = errors.New("syscalllist: table length cannot be found")
)

type table struct {
	symbol     string
	prefix     string
	dispatcher string
}

// With 4-byte pointers sys_call_table is the i386 table, and ia32 and x32
// tables do not exist (S11 T5, T7).
func tables(width uint64) []table {
	if width == 4 {
		return []table{{"sys_call_table", "__ia32_", "ia32_sys_call"}}
	}
	return []table{
		{"sys_call_table", "__x64_", "x64_sys_call"},
		{"ia32_sys_call_table", "__ia32_", "ia32_sys_call"},
		{"x32_sys_call_table", "__x64_", "x32_sys_call"},
	}
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Row, error) {
	k, err := linuxkern.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	if !k.HasSymbol("sys_call_table") {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoTable)
	}
	model, err := k.Modules()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	c := &checker{k: k, model: model, limit: uint64(max(ctx.Bounds().MaxTableEntries, 0))}
	var out []Row
	for _, t := range tables(k.PtrSize) {
		if !k.HasSymbol(t.symbol) {
			continue
		}
		rows, err := c.table(t)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		out = append(out, rows...)
	}
	return out, nil
}

type checker struct {
	k        *linuxkern.Kernel
	model    *linuxmodule.Model
	limit    uint64
	listed   []symbols.Symbol
	listErr  error
	listDone bool
	gathered bool
	known    []linuxmodule.Module
}

func (c *checker) table(t table) ([]Row, error) {
	k := c.k
	at, err := k.Symbol(t.symbol)
	if err != nil {
		return nil, err
	}
	words, ok, err := c.entries(t.symbol, at)
	if err != nil {
		return nil, fmt.Errorf("%s at %#x: %w", t.symbol, at, err)
	}
	names := preferring(k, t.prefix)
	dispatches := !k.HasSymbol(t.dispatcher)
	var out []Row
	unread := 0
	for i, w := range words {
		if !ok[i] {
			unread++
			continue
		}
		row := Row{TableAddress: at, TableName: t.symbol, Index: uint64(i), HandlerAddress: w & k.Mask, Dispatches: dispatches}
		module, symbol, err := c.owner(row.HandlerAddress, names)
		if err != nil {
			return nil, err
		}
		row.Module, row.HandlerSymbol = module, symbol
		out = append(out, row)
	}
	if unread > 0 {
		k.Diag("%s: %s at %#x: %d entries unreadable and left out", Name, t.symbol, at, unread)
		if k.Context().StrictMode() {
			return nil, fmt.Errorf("strict mode: %s at %#x: %d entries unreadable", t.symbol, at, unread)
		}
	}
	return out, nil
}

// A declared array type gives the length directly. Without one, the table
// ends before the next symbol, and the generated tables have no null entry
// (S11 T2), so null words before that symbol are padding (S11 M2).
func (c *checker) entries(name string, at uint64) ([]uint64, []bool, error) {
	k := c.k
	if ref, err := k.SymbolTypeRef(name); err == nil && ref.ArrayLength > 0 {
		n := ref.ArrayLength
		if n > c.limit {
			if err := c.capped(name, at, n); err != nil {
				return nil, nil, err
			}
			n = c.limit
		}
		words, ok := c.read(at, n)
		return words, ok, nil
	}
	bound, err := c.bound(name)
	if err != nil {
		return nil, nil, err
	}
	if bound > c.limit {
		if err := c.capped(name, at, bound); err != nil {
			return nil, nil, err
		}
		bound = c.limit
	}
	words, ok := c.read(at, bound)
	n := trimmedLength(words, ok)
	if n == 0 {
		return nil, nil, ErrNoSize
	}
	return words[:n], ok[:n], nil
}

func (c *checker) capped(name string, at, n uint64) error {
	c.k.Diag("%s: %s at %#x: %d entries cut to %d", Name, name, at, n, c.limit)
	if c.k.Context().StrictMode() {
		return fmt.Errorf("strict mode: %d entries over the table cap", n)
	}
	return nil
}

func (c *checker) bound(name string) (uint64, error) {
	if !c.listDone {
		c.listDone = true
		var listed []symbols.Symbol
		listed, c.listErr = c.k.TableSymbols()
		c.listed = append([]symbols.Symbol(nil), listed...)
		sort.Slice(c.listed, func(i, j int) bool { return c.listed[i].Address&c.k.Mask < c.listed[j].Address&c.k.Mask })
	}
	if c.listErr != nil {
		return 0, fmt.Errorf("%w: %w", ErrNoSize, c.listErr)
	}
	var linked uint64
	found := false
	for _, s := range c.listed {
		if s.Name == name {
			linked, found = s.Address&c.k.Mask, true
			break
		}
	}
	if !found {
		return 0, fmt.Errorf("%w: the symbol list does not hold %s", ErrNoSize, name)
	}
	i := sort.Search(len(c.listed), func(i int) bool { return c.listed[i].Address&c.k.Mask > linked })
	if i == len(c.listed) {
		return c.limit, nil
	}
	return (c.listed[i].Address&c.k.Mask - linked) / c.k.PtrSize, nil
}

func (c *checker) read(at, n uint64) ([]uint64, []bool) {
	words, ok := make([]uint64, n), make([]bool, n)
	for i := range n {
		w, err := c.k.ReadUint(at+i*c.k.PtrSize, c.k.PtrSize)
		words[i], ok[i] = w, err == nil
	}
	return words, ok
}

// trimmedLength drops only trailing entries that read as null: an unreadable
// entry may be a real one and is kept, to be counted as unread.
func trimmedLength(words []uint64, ok []bool) uint64 {
	for i := min(len(words), len(ok)) - 1; i >= 0; i-- {
		if !ok[i] || words[i] != 0 {
			return uint64(i) + 1
		}
	}
	return 0
}

// Stubs of several ABIs can share one address (the ni_syscall aliases), so
// the name with the table's own stub prefix is put first (S11 T9).
func preferring(k *linuxkern.Kernel, prefix string) linuxmodule.KernelNamer {
	return func(a uint64) []string {
		names, _ := k.SymbolsAt(a)
		for i, n := range names {
			if strings.HasPrefix(n, prefix) {
				return append([]string{n}, append(names[:i:i], names[i+1:]...)...)
			}
		}
		return names
	}
}

func (c *checker) owner(addr uint64, names linuxmodule.KernelNamer) (string, string, error) {
	if o := c.model.Lookup(nil, addr, names); o.Found {
		module, symbol := o.Names()
		return module, symbol, nil
	}
	if err := c.gather(); err != nil {
		return "", "", err
	}
	module, symbol := c.model.Lookup(c.known, addr, names).Names()
	return module, symbol, nil
}

// Modules are gathered only for a handler outside the kernel image, which a
// clean kernel never has (S11 M3), so a clean run skips the module scan.
func (c *checker) gather() error {
	if c.gathered {
		return nil
	}
	c.gathered = true
	vs, err := c.model.Views()
	vs.Report(c.k.Diag, Name)
	strict := c.k.Context().StrictMode()
	if err != nil {
		if strict {
			return fmt.Errorf("strict mode: no module view: %w", err)
		}
		return nil
	}
	if vs.Lossy() && strict {
		return errors.New("strict mode: the module views left modules out")
	}
	c.known = vs.Known()
	return nil
}
