package linuxobjtest

import (
	"encoding/binary"
	"sort"

	"github.com/aoiflux/libvapour/symbols"
)

// S38 layouts follow the 6.17 offsets measured in S38 S1.
const (
	LatchRootSize     = 0x18
	LatchRootTree     = 0x08
	RBNodeSize        = 0x18
	RBNodeRight       = 0x08
	RBNodeLeft        = 0x10
	LatchNodeSize     = 2 * RBNodeSize
	ModTreeRootSize   = 0x28
	ModTreeRootMin    = 0x18
	ModTreeRootMax    = 0x20
	ModuleMemorySize  = 0x48
	ModuleMemoryMtn   = 0x10
	ModTreeNodeNode   = 0x08
	BPFKsymTnode      = 0x220
	ProgAuxSize       = 0x100
	ProgAuxTnode      = 0x20
	ProgAuxLnode      = 0x50
	ProgAuxProg       = 0x60
	ProgAuxName       = 0x70
	ProgSize          = 0x48
	ProgTag           = 0x18
	ProgFunc          = 0x30
	ProgAuxNameLength = 16
	progTagLength     = 8
)

func (k *Kernel) addLatchTypes() {
	t := k.Table
	f := func(name string, off uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: typ}
	}
	t.AddStruct(symbols.StructType{Name: "rb_node", Size: RBNodeSize, Fields: []symbols.Field{
		f("__rb_parent_color", 0, scalar("long long unsigned int")), f("rb_right", RBNodeRight, ptr("rb_node")),
		f("rb_left", RBNodeLeft, ptr("rb_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "rb_root", Size: 8, Fields: []symbols.Field{f("rb_node", 0, ptr("rb_node"))}})
	t.AddStruct(symbols.StructType{Name: "latch_tree_node", Size: LatchNodeSize, Fields: []symbols.Field{
		f("node", 0, array("rb_node", 2)),
	}})
	t.AddStruct(symbols.StructType{Name: "latch_tree_root", Size: LatchRootSize, Fields: []symbols.Field{
		f("seq", 0, scalar("seqcount_latch_t")), f("tree", LatchRootTree, array("rb_root", 2)),
	}})
}

// LatchTree links the latch_tree_nodes, given in key order, into both copies
// of the tree at root as a balanced search tree, and stores seq.
func (k *Kernel) LatchTree(root uint64, seq uint32, nodes []uint64) {
	k.addLatchTypes()
	k.Mem.U32(root, seq)
	for idx := uint64(0); idx < 2; idx++ {
		k.Mem.U64(root+LatchRootTree+8*idx, k.latchSubtree(nodes, idx))
	}
}

func (k *Kernel) latchSubtree(nodes []uint64, idx uint64) uint64 {
	if len(nodes) == 0 {
		return 0
	}
	mid := len(nodes) / 2
	rb := nodes[mid] + idx*RBNodeSize
	k.Mem.U64(rb+RBNodeLeft, k.latchSubtree(nodes[:mid], idx))
	k.Mem.U64(rb+RBNodeRight, k.latchSubtree(nodes[mid+1:], idx))
	return rb
}

type ModuleTree struct {
	k    *Kernel
	Mods *Modules
	Root uint64
}

// AddModuleTree replaces the module memory and mod_tree types with the 6.17
// forms that hold tree nodes. Call it before Modules.Add.
func AddModuleTree(k *Kernel, m *Modules) *ModuleTree {
	k.addLatchTypes()
	t := k.Table
	f := func(name string, off uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: typ}
	}
	voidp := symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}
	t.AddStruct(symbols.StructType{Name: "mod_tree_node", Size: 8 + LatchNodeSize, Fields: []symbols.Field{
		f("mod", 0, ptr("module")), f("node", ModTreeNodeNode, scalar("latch_tree_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "module_memory", Size: ModuleMemorySize, Fields: []symbols.Field{
		f("base", 0, voidp), f("size", 8, scalar("unsigned int")), f("mtn", ModuleMemoryMtn, scalar("mod_tree_node")),
	}})
	t.AddStruct(symbols.StructType{Name: "mod_tree_root", Size: ModTreeRootSize, Fields: []symbols.Field{
		f("root", 0, scalar("latch_tree_root")), f("addr_min", ModTreeRootMin, scalar("long long unsigned int")),
		f("addr_max", ModTreeRootMax, scalar("long long unsigned int")),
	}})
	root := k.Alloc(ModTreeRootSize)
	t.AddSymbol(symbols.Symbol{Name: "mod_tree", Address: root, Type: "mod_tree_root"})
	return &ModuleTree{k: k, Mods: m, Root: root}
}

func (t *ModuleTree) Bounds(lo, hi uint64) {
	t.k.Mem.U64(t.Root+ModTreeRootMin, lo)
	t.k.Mem.U64(t.Root+ModTreeRootMax, hi)
}

type RegionRef struct {
	Module uint64
	Kind   int
}

// RegionNode is the latch_tree_node of module.mem[kind].
func RegionNode(r RegionRef) uint64 {
	return r.Module + ModuleMem + uint64(r.Kind)*ModuleMemorySize + ModuleMemoryMtn + ModTreeNodeNode
}

// Build sets each region's mtn.mod and links the regions into the tree in
// base order.
func (t *ModuleTree) Build(seq uint32, regions ...RegionRef) {
	k := t.k
	type keyed struct{ base, node uint64 }
	var nodes []keyed
	for _, r := range regions {
		at := r.Module + ModuleMem + uint64(r.Kind)*ModuleMemorySize
		k.Mem.U64(at+ModuleMemoryMtn, r.Module)
		b, err := k.Mem.ReadAt(at, 8)
		if err != nil {
			panic(err)
		}
		nodes = append(nodes, keyed{binary.LittleEndian.Uint64(b), RegionNode(r)})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].base < nodes[j].base })
	ordered := make([]uint64, len(nodes))
	for i, n := range nodes {
		ordered[i] = n.node
	}
	k.LatchTree(t.Root, seq, ordered)
}

// BPFTree adds tnode to the bpf_ksym type of AddKallsymsLists and links the
// given bpf_ksym structures, in start order, into bpf_tree.
func (l *KallsymsLists) BPFTree(seq uint32, ksyms ...uint64) uint64 {
	k := l.k
	st, err := k.Table.Struct("bpf_ksym")
	if err != nil {
		panic(err)
	}
	st.Fields = append(st.Fields, symbols.Field{Name: "tnode", Offset: BPFKsymTnode, Type: scalar("latch_tree_node")})
	k.Table.AddStruct(st)
	root := k.Alloc(LatchRootSize)
	k.Table.AddSymbol(symbols.Symbol{Name: "bpf_tree", Address: root, Type: "latch_tree_root"})
	nodes := make([]uint64, len(ksyms))
	for i, s := range ksyms {
		nodes[i] = s + BPFKsymTnode
	}
	k.LatchTree(root, seq, nodes)
	return root
}

type ProgAux struct {
	k          *Kernel
	head, root uint64
	nodes      []uint64
}

type BPFProgram struct {
	Name  string
	Tag   [progTagLength]byte
	Func  uint64
	Pages uint32
}

// AddProgAux sets up the v4.19 BPF form: programs found through
// bpf_prog_aux.ksym_lnode and ksym_tnode.
func AddProgAux(k *Kernel) *ProgAux {
	k.addLatchTypes()
	t := k.Table
	f := func(name string, off uint64, typ symbols.TypeRef) symbols.Field {
		return symbols.Field{Name: name, Offset: off, Type: typ}
	}
	t.AddStruct(symbols.StructType{Name: "bpf_prog_aux", Size: ProgAuxSize, Fields: []symbols.Field{
		f("ksym_tnode", ProgAuxTnode, scalar("latch_tree_node")), f("ksym_lnode", ProgAuxLnode, scalar("list_head")),
		f("prog", ProgAuxProg, ptr("bpf_prog")), f("name", ProgAuxName, array("char", ProgAuxNameLength)),
	}})
	t.AddStruct(symbols.StructType{Name: "bpf_prog", Size: ProgSize, Fields: []symbols.Field{
		f("tag", ProgTag, array("unsigned char", progTagLength)),
		f("bpf_func", ProgFunc, symbols.TypeRef{IsPointer: true, Element: &symbols.TypeRef{Name: "void"}}),
	}})
	p := &ProgAux{k: k, head: k.Alloc(16), root: k.Alloc(LatchRootSize)}
	k.Circle(p.head)
	t.AddSymbol(symbols.Symbol{Name: "bpf_kallsyms", Address: p.head, Type: "list_head"})
	t.AddSymbol(symbols.Symbol{Name: "bpf_tree", Address: p.root, Type: "latch_tree_root"})
	return p
}

// Add lays out one program; its header page holds the page count. Add
// programs in start order.
func (p *ProgAux) Add(prog BPFProgram) uint64 {
	k := p.k
	aux := k.Alloc(ProgAuxSize)
	pr := k.Alloc(ProgSize)
	k.Mem.U64(aux+ProgAuxProg, pr)
	name := make([]byte, ProgAuxNameLength)
	copy(name, prog.Name)
	k.Mem.Write(aux+ProgAuxName, name)
	k.Mem.Write(pr+ProgTag, prog.Tag[:])
	k.Mem.U64(pr+ProgFunc, prog.Func)
	hdr := prog.Func &^ (pageSize - 1)
	k.Mem.Map(hdr, 4)
	k.Mem.U32(hdr, prog.Pages)
	heads := []uint64{p.head}
	p.nodes = append(p.nodes, aux+ProgAuxTnode)
	for _, n := range p.nodes {
		heads = append(heads, n-ProgAuxTnode+ProgAuxLnode)
	}
	k.Circle(heads...)
	k.LatchTree(p.root, 0, p.nodes)
	return aux
}
