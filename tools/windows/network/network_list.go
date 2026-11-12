package network

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/pesymbols"
	"github.com/aoiflux/libvapour/tools/winkernel"
)

const NetworkListName = "windows.network.list"

const optionNetworkListIncludeCorrupt = "windows.network.list.include_corrupt"

const OptionNetworkListIncludeCorrupt = optionNetworkListIncludeCorrupt

const (
	tcpipModule           = "tcpip.sys"
	globalPartitionTable  = "PartitionTable"
	globalPartitionCount  = "PartitionCount"
	globalTCPCompartments = "TcpCompartmentSet"
	globalUDPCompartments = "UdpCompartmentSet"
)

// RFC 9293 3.1 makes a port 16 bits wide: the pool's bitmap spends one bit on
// each, and its assignment array cuts the range into 256 blocks of 256 (M5).
const (
	portSpace      = 1 << 16
	portBlockShift = 8
	portBlock      = 1 << portBlockShift
)

// Measured on every capture (M5, M6): the two low bits of a port pool entry
// are flags, and in the TCP pool only a value of 2 starts a listener chain.
const (
	entryFlagBits    = uint64(3)
	tcpListenerFlags = uint64(2)
)

// Every measured endpoint table has 128 buckets, laid out as one array of
// list heads (M2); a larger table's directory was never seen.
const maxFlatBuckets = 128

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        NetworkListName,
			Description: "Connections, listeners and UDP endpoints held in tcpip.sys's partition hash tables and port pools",
		},
		RunNetworkListAny,
	)
}

func RunNetworkListAny(ctx tools.Context) (any, error) {
	return RunNetworkList(ctx)
}

func checkContext(ctx tools.Context) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return ErrNotWindows
	}
	if ctx.Symbols.PointerSize() != pointerBytes {
		return ErrPointerSize
	}
	return nil
}

type tcpipGlobals struct {
	partitionTable, partitionCount uint64
	compartments                   map[EndpointKind]uint64
}

func resolveGlobals(ctx tools.Context) (tcpipGlobals, error) {
	names := []string{globalPartitionTable, globalPartitionCount, globalTCPCompartments, globalUDPCompartments}
	found, missing, err := pesymbols.Resolve(ctx, pesymbols.SourceKernel, map[string][]string{tcpipModule: names})
	if len(missing[tcpipModule]) > 0 || len(found[tcpipModule]) == 0 {
		if err == nil {
			err = fmt.Errorf("missing %s", strings.Join(missing[tcpipModule], ", "))
		}
		return tcpipGlobals{}, fmt.Errorf("%s: %w: %w", NetworkListName, ErrTcpipSymbols, err)
	}
	at := map[string]uint64{}
	for _, s := range found[tcpipModule] {
		if _, seen := at[s.Name]; !seen {
			at[s.Name] = s.Address
		}
	}
	return tcpipGlobals{
		partitionTable: at[globalPartitionTable],
		partitionCount: at[globalPartitionCount],
		compartments:   map[EndpointKind]uint64{KindListener: at[globalTCPCompartments], KindDatagram: at[globalUDPCompartments]},
	}, nil
}

type lister struct {
	ctx      tools.Context
	d        decoder
	t        *tableMembers
	include  bool
	seen     map[uint64]bool
	rows     []Endpoint
	rejected map[string]int
}

func RunNetworkList(ctx tools.Context) ([]Endpoint, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	include, err := ctx.BoolOption(optionNetworkListIncludeCorrupt)
	if err != nil {
		return nil, err
	}
	l, err := resolveLayout(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", NetworkListName, err)
	}
	if l.tables == nil {
		return nil, fmt.Errorf("%s: layout %q: %w", NetworkListName, l.name, ErrNoTables)
	}
	g, err := resolveGlobals(ctx)
	if err != nil {
		return nil, err
	}
	return listTables(ctx, l, g, include)
}

func listTables(ctx tools.Context, l *objectLayout, g tcpipGlobals, include bool) ([]Endpoint, error) {
	ls := &lister{ctx: ctx, d: newDecoder(ctx, l), t: l.tables, include: include,
		seen: map[uint64]bool{}, rejected: map[string]int{}}
	if err := ls.connections(g); err != nil {
		return nil, err
	}
	for _, k := range []EndpointKind{KindListener, KindDatagram} {
		if err := ls.portPool(k, g.compartments[k]); err != nil {
			return nil, err
		}
	}
	ls.report()
	sortListed(ls.rows)
	return keepPIDs(ctx, ls.rows), nil
}

func (ls *lister) keep(e Endpoint, at uint64, err error) {
	e.ObjectAddress = at
	if err != nil {
		ls.rejected[err.Error()]++
		if !ls.include {
			return
		}
		e.Rejected = err.Error()
	}
	ls.rows = append(ls.rows, e)
}

func (ls *lister) report() {
	if len(ls.rejected) == 0 {
		return
	}
	reasons := make([]string, 0, len(ls.rejected))
	total := 0
	for r, n := range ls.rejected {
		reasons = append(reasons, fmt.Sprintf("%d %s", n, strings.TrimPrefix(r, "network: ")))
		total += n
	}
	sort.Strings(reasons)
	verb := "not listed"
	if ls.include {
		verb = "listed with Rejected set"
	}
	ls.ctx.AddDiagnostic("%s: %d objects %s: %s", NetworkListName, total, verb, strings.Join(reasons, "; "))
}

func (ls *lister) fail(err error) error {
	if ls.ctx.StrictMode() {
		return err
	}
	ls.ctx.AddDiagnostic("%v", err)
	return nil
}

func (ls *lister) connections(g tcpipGlobals) error {
	kernel := ls.ctx.Memory
	table, ok := readPointer(kernel, g.partitionTable)
	count, okCount := readU32(kernel, g.partitionCount)
	if !ok || !okCount || !systemSpace(table) {
		return ls.fail(fmt.Errorf("%s: partition table at 0x%x: pointer or count unread or outside system space: %w",
			NetworkListName, g.partitionTable, ErrObjectUnread))
	}
	partitions := uint64(count)
	if limit := uint64(ls.ctx.Bounds().MaxTableEntries); partitions > limit {
		if err := ls.fail(fmt.Errorf("%s: partition table at 0x%x: %d partitions, more than MaxTableEntries %d",
			NetworkListName, table, count, limit)); err != nil {
			return err
		}
		partitions = limit
	}
	layout, err := winkernel.NativeListLayout(ls.ctx.Symbols)
	if err != nil {
		return fmt.Errorf("%s: %w", NetworkListName, err)
	}
	walker := winkernel.ListWalker{Tool: NetworkListName, Memory: kernel, Layout: layout,
		Limit: ls.ctx.Bounds().MaxListEntries, Strict: ls.ctx.StrictMode(), Report: ls.ctx.AddDiagnostic}
	for i := range partitions {
		partition := table + i*ls.t.partitionSize
		hash, ok := readPointer(kernel, partition+ls.t.endpoints)
		if !ok || !systemSpace(hash) {
			if err := ls.fail(fmt.Errorf("%s: partition at 0x%x: endpoint table pointer unread or outside system space: %w",
				NetworkListName, partition, ErrObjectUnread)); err != nil {
				return err
			}
			continue
		}
		if err := ls.hashTable(walker, hash); err != nil {
			return err
		}
	}
	return nil
}

func (ls *lister) hashTable(walker winkernel.ListWalker, hash uint64) error {
	kernel := ls.ctx.Memory
	size, okSize := readU32(kernel, hash+ls.t.hashTableSize.Offset)
	entries, okEntries := readU32(kernel, hash+ls.t.hashEntries.Offset)
	dir, okDir := readPointer(kernel, hash+ls.t.hashDirectory.Offset)
	if !okSize || !okEntries || !okDir || !systemSpace(dir) {
		return ls.fail(fmt.Errorf("%s: endpoint table at 0x%x: header unread or directory outside system space: %w",
			NetworkListName, hash, ErrObjectUnread))
	}
	if size == 0 || size > maxFlatBuckets {
		return ls.fail(fmt.Errorf("%s: endpoint table at 0x%x: TableSize %d has no measured directory form: %w",
			NetworkListName, hash, size, ErrNoTables))
	}
	walked := 0
	for b := range uint64(size) {
		head := dir + b*ls.t.listEntrySize
		w, err := walker.WalkRecovering(head, "endpoint bucket")
		if err != nil {
			if ls.ctx.StrictMode() {
				return err
			}
			ls.ctx.AddDiagnostic("%v", err)
			continue
		}
		for _, entry := range w.Entries {
			at, ok := winkernel.Container(entry, ls.d.l.connection.link)
			if !ok || ls.seen[at] {
				continue
			}
			ls.seen[at] = true
			walked++
			e, err := ls.d.connection(kernel, at)
			ls.keep(e, at, err)
		}
	}
	if walked != int(entries) {
		ls.ctx.AddDiagnostic("%s: endpoint table at 0x%x: walked %d entries, NumEntries is %d",
			NetworkListName, hash, walked, entries)
	}
	return nil
}

func (ls *lister) portPool(kind EndpointKind, global uint64) error {
	kernel := ls.ctx.Memory
	where := fmt.Sprintf("%s: %s port pool from 0x%x", NetworkListName, kind.Protocol(), global)
	pool, err := ls.follow(global, 0, ls.t.compartment, ls.t.protocol, ls.t.portPool)
	if err != nil {
		return ls.fail(fmt.Errorf("%s: %w", where, err))
	}
	bits, okBits := readU32(kernel, pool+ls.t.bitmap+ls.t.bitmapBits.Offset)
	buffer, okBuffer := readPointer(kernel, pool+ls.t.bitmap+ls.t.bitmapBuffer.Offset)
	if !okBits || !okBuffer || bits != portSpace || !systemSpace(buffer) {
		return ls.fail(fmt.Errorf("%s: port bitmap at 0x%x: %d bits, buffer 0x%x: %w",
			where, pool+ls.t.bitmap, bits, buffer, ErrObjectUnread))
	}
	used, err := kernel.ReadAt(buffer, portSpace/8)
	if err != nil || len(used) < portSpace/8 {
		return ls.fail(fmt.Errorf("%s: port bitmap buffer at 0x%x: %w", where, buffer, ErrObjectUnread))
	}
	held := 0
	m := ls.d.l.bound(kind)
	for port := range portSpace {
		if used[port/8]>>(port%8)&1 == 0 {
			continue
		}
		block, ok := readPointer(kernel, pool+ls.t.assignments+uint64(port>>portBlockShift)*pointerBytes)
		if !ok || block == 0 {
			continue
		}
		list, ok := readPointer(kernel, block+ls.t.assignmentList)
		if !ok || !systemSpace(list) {
			continue
		}
		head, ok := readPointer(kernel, list+ls.t.entryObject+uint64(port%portBlock)*ls.t.entrySize)
		if !ok || head&^entryFlagBits == 0 {
			continue
		}
		if kind == KindListener && head&entryFlagBits != tcpListenerFlags {
			held++
			continue
		}
		if err := ls.chain(kind, m, uint16(port), head); err != nil {
			return err
		}
	}
	if held > 0 {
		ls.ctx.AddDiagnostic("%s: %d ports held by entries that are not listeners", where, held)
	}
	return nil
}

// Each entry points at the next member of the first endpoint bound to the
// port, and each endpoint's next member at the next one's (M5).
func (ls *lister) chain(kind EndpointKind, m boundMembers, port uint16, link uint64) error {
	limit := ls.ctx.Bounds().MaxListEntries
	for n := 0; link&^entryFlagBits != 0; n++ {
		next := link &^ entryFlagBits
		at, ok := winkernel.Container(next, m.next)
		if !ok || !systemSpace(next) || ls.seen[at] {
			return nil
		}
		if n >= limit {
			return ls.fail(fmt.Errorf("%s: %s port %d chain at 0x%x: more than MaxListEntries %d",
				NetworkListName, kind.Protocol(), port, next, limit))
		}
		ls.seen[at] = true
		e, err := ls.d.bound(ls.ctx.Memory, kind, at)
		if err == nil && e.LocalPort != port {
			err = ErrBoundPort
		}
		ls.keep(e, at, err)
		if link, ok = readPointer(ls.ctx.Memory, next); !ok {
			return ls.fail(fmt.Errorf("%s: %s %s at 0x%x: next link unread: %w",
				NetworkListName, kind.Protocol(), kind, at, ErrObjectUnread))
		}
	}
	return nil
}

func (ls *lister) follow(at uint64, offsets ...uint64) (uint64, error) {
	p := at
	for _, off := range offsets {
		v, ok := readPointer(ls.ctx.Memory, p+off)
		if !ok || !systemSpace(v) {
			return 0, fmt.Errorf("pointer at 0x%x: 0x%x: %w", p+off, v, ErrPointer)
		}
		p = v
	}
	return p, nil
}

var kindOrder = map[EndpointKind]int{KindConnection: 0, KindListener: 1, KindDatagram: 2}

func keepPIDs(ctx tools.Context, rows []Endpoint) []Endpoint {
	pids := ctx.PIDs()
	if !pids.All() {
		rows = slices.DeleteFunc(rows, func(e Endpoint) bool { return !pids.Keep(e.OwningPID) })
	}
	return rows
}

func sortListed(rows []Endpoint) {
	slices.SortStableFunc(rows, func(a, b Endpoint) int {
		if c := cmp.Compare(kindOrder[a.Kind], kindOrder[b.Kind]); c != 0 {
			return c
		}
		return cmp.Compare(a.ObjectAddress, b.ObjectAddress)
	})
}
