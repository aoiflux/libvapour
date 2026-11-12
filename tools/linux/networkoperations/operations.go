package networkoperations

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/linuxmodule"
	"github.com/aoiflux/libvapour/tools/linuxobj"
)

const Name = "linux.network.check_operations"

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "Check that the functions behind each /proc/net listing are in the kernel or in the module that holds the listing",
		},
		RunAny,
	)
}

type Verdict string

const (
	VerdictExpected    Verdict = "expected"
	VerdictNotSet      Verdict = "not set"
	VerdictNoOwner     Verdict = "outside the kernel and modules"
	VerdictOtherModule Verdict = "in another module"
	VerdictMidFunction Verdict = "not at a function start"
	VerdictUnnamed     Verdict = "module symbols do not read"
	VerdictTableUnread Verdict = "table does not read"
)

const (
	tableTypeName    = "seq_operations"
	procNetDirectory = "/proc/net/"
	kernelOwner      = linuxmodule.KernelOwner
)

type Handler struct {
	Table         string
	TableAddress  uint64
	ProcFile      string
	TableModule   string
	Member        string
	TargetAddress uint64
	Module        string
	Symbol        string
	Verdict       Verdict
}

var (
	ErrNoOperationsType = errors.New("networkoperations: symbol table has no seq_operations type")
	ErrNoTables         = errors.New("networkoperations: symbol table has none of the /proc/net seq_operations tables")
)

// S62 NO2, NO3: the tables behind the /proc/net files, by the name each
// protocol registers with proc_create_net or proc_create_net_data.
var listings = []struct{ table, file string }{
	{"tcp4_seq_ops", "tcp"},
	{"tcp6_seq_ops", "tcp6"},
	{"udp_seq_ops", "udp"},
	{"udp6_seq_ops", "udp6"},
	{"raw_seq_ops", "raw"},
	{"raw6_seq_ops", "raw6"},
	{"ping_v4_seq_ops", "icmp"},
	{"ping_v6_seq_ops", "icmp6"},
	{"unix_seq_ops", "unix"},
	{"packet_seq_ops", "packet"},
	{"netlink_seq_ops", "netlink"},
	{"arp_seq_ops", "arp"},
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

func Run(ctx tools.Context) ([]Handler, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "linux") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	k := linuxobj.New(ctx)
	members, err := operationMembers(k.Symbols())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	var present []int
	var missing []string
	for i, l := range listings {
		if k.HasSymbol(l.table) {
			present = append(present, i)
		} else {
			missing = append(missing, l.table)
		}
	}
	if len(present) == 0 {
		return nil, fmt.Errorf("%s: %w", Name, ErrNoTables)
	}
	if len(missing) > 0 {
		ctx.AddDiagnostic("%s: not in the symbol table, so not checked: %s", Name, strings.Join(missing, ", "))
	}
	o, err := newOwners(ctx, k)
	if err != nil {
		return nil, err
	}
	unread := 0
	var out []Handler
	for _, i := range present {
		l := listings[i]
		s, err := k.Symbol(l.table)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", Name, err)
		}
		at := s.Address
		tableOwner := o.tableOwner(at)
		failed := false
		for _, m := range members {
			h := Handler{Table: l.table, TableAddress: k.Masked(at), ProcFile: procNetDirectory + l.file,
				TableModule: tableOwner, Member: m.Name}
			v, err := k.PointerAt(k.Memory(), at+m.Offset)
			if err != nil {
				unread++
				if !failed {
					failed = true
					ctx.AddDiagnostic("%s: %s at %#x: %s does not read: %v", Name, l.table, k.Masked(at), m.Name, err)
				}
				h.Verdict = VerdictTableUnread
				out = append(out, h)
				continue
			}
			h.TargetAddress = k.Masked(v)
			h.Module, h.Symbol, h.Verdict = o.judge(v, tableOwner)
			out = append(out, h)
		}
	}
	if ctx.StrictMode() && (unread > 0 || o.lossy) {
		return nil, fmt.Errorf("%s: strict mode: %d operations did not read or the module views were read in part", Name, unread)
	}
	return out, nil
}

// S62 NO1: every member of struct seq_operations is a function pointer.
func operationMembers(t symbols.SymbolTable) ([]symbols.Field, error) {
	st, err := t.Struct(tableTypeName)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoOperationsType, err)
	}
	var out []symbols.Field
	for _, f := range st.Fields {
		if f.Type.IsPointer {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoOperationsType
	}
	slices.SortStableFunc(out, func(a, b symbols.Field) int { return cmp.Compare(a.Offset, b.Offset) })
	return out, nil
}

type owners struct {
	k     *linuxobj.Kernel
	model *linuxmodule.Model
	known []linuxmodule.Module
	lossy bool
}

func newOwners(ctx tools.Context, k *linuxobj.Kernel) (*owners, error) {
	o := &owners{k: k}
	model, err := k.Modules()
	if err != nil {
		return nil, fmt.Errorf("%s: module model: %w", Name, err)
	}
	vs, err := model.Views()
	if err != nil {
		return nil, fmt.Errorf("%s: module views: %w", Name, err)
	}
	vs.Report(ctx.AddDiagnostic, Name)
	o.model, o.known, o.lossy = model, vs.Known(), vs.Lossy()
	return o, nil
}

// S62 NO4: a table that no module region holds is part of the kernel image;
// the lookup finds kernel text only, and the table is read-only data.
func (o *owners) tableOwner(at uint64) string {
	if own := o.model.Lookup(o.known, at, nil); own.Found && !own.Kernel {
		return own.Module.Name
	}
	return kernelOwner
}

// S62 NO3, NO5: the first rule a target fails names the finding.
func (o *owners) judge(target uint64, tableOwner string) (module, symbol string, v Verdict) {
	if o.k.Masked(target) == 0 {
		return "", "", VerdictNotSet
	}
	own := o.model.Lookup(o.known, target, o.k.SymbolsAt)
	if !own.Found {
		return "", "", VerdictNoOwner
	}
	module = kernelOwner
	if !own.Kernel {
		module = own.Module.Name
	}
	symbol = own.Symbol
	if own.Symbol != "" && own.Offset != 0 {
		symbol = fmt.Sprintf("%s+%#x", own.Symbol, own.Offset)
	}
	switch {
	case module != kernelOwner && module != tableOwner:
		return module, symbol, VerdictOtherModule
	case own.Unnamed:
		return module, symbol, VerdictUnnamed
	case own.Symbol == "" || own.Offset != 0:
		return module, symbol, VerdictMidFunction
	}
	return module, symbol, VerdictExpected
}
