package executionamcache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/util"
)

const Name = "windows.execution.read_amcache"

var (
	ErrNoHive     = errors.New("executionamcache: no Amcache hive opens")
	ErrIncomplete = errors.New("executionamcache: inventory not read in full")
)

type Category string

const (
	ApplicationFile Category = "application_file"
	Application     Category = "application"
	DriverBinary    Category = "driver_binary"
)

type InventoryRecord struct {
	HivePath    string
	HiveAddress uint64
	Category    Category

	Key           string
	KeyUnreadable bool
	KeyLastWrite  time.Time

	Path        string
	Name        string
	FileID      string
	FileIDHash  string
	ProgramID   string
	Publisher   string
	Product     string
	Version     string
	LinkDate    string
	InstallDate string
	LinkTime    time.Time
	Service     string

	Unread []string
}

func init() {
	tools.MustRegister(
		tools.Spec{
			Name:        Name,
			Description: "List the Amcache hive's inventory of program files, applications and driver binaries: path, name, file identifier, program identifier, publisher, product, version and link time",
		},
		RunAny,
	)
}

func RunAny(ctx tools.Context) (any, error) { return Run(ctx) }

type inventoryHive interface {
	OpenKey(path string) (*registryhive.KeyNode, error)
	SubkeysChecked(node *registryhive.KeyNode) ([]*registryhive.KeyNode, bool)
	ValuesChecked(node *registryhive.KeyNode) ([]registryhive.Value, bool)
}

func Run(ctx tools.Context) ([]InventoryRecord, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(ctx.Profile.OS(), "windows") {
		return nil, fmt.Errorf("%s: unsupported profile os %q", Name, ctx.Profile.OS())
	}
	for _, o := range registryhive.OpenEveryHive(ctx, nil) {
		if strings.Contains(strings.ToLower(hivePath(o.Hive)+" "+o.Hive.RegistryPath), "amcache") {
			return read(ctx, o.Layer, hiveID{path: hivePath(o.Hive), address: o.Hive.Address})
		}
	}
	return nil, fmt.Errorf("%s: %w", Name, ErrNoHive)
}

func hivePath(h registryhive.Hive) string {
	if h.FileFullPath != "" {
		return h.FileFullPath
	}
	return h.Name
}

type hiveID struct {
	path    string
	address uint64
}

var inventories = []struct {
	key      string
	category Category
}{
	{`Root\InventoryApplicationFile`, ApplicationFile},
	{`Root\InventoryApplication`, Application},
	{`Root\InventoryDriverBinary`, DriverBinary},
}

var undecoded = []string{`Root\File`, `Root\Programs`}

func read(ctx tools.Context, h inventoryHive, id hiveID) ([]InventoryRecord, error) {
	var out []InventoryRecord
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, inv := range inventories {
		key, err := h.OpenKey(inv.key)
		switch {
		case errors.Is(err, registryhive.ErrKeyNotFound):
			continue
		case err != nil:
			ctx.AddDiagnostic("%s: hive at 0x%x: key %s not read: %v", Name, id.address, inv.key, err)
			fail(fmt.Errorf("%s: %s: %w", Name, inv.key, ErrIncomplete))
			continue
		}
		subs, complete := h.SubkeysChecked(key)
		if !complete {
			ctx.AddDiagnostic("%s: key at 0x%x: subkey list not read in full: %v", Name, key.Address, ErrIncomplete)
			fail(fmt.Errorf("%s: %s subkeys: %w", Name, inv.key, ErrIncomplete))
		}
		unread := 0
		for _, sk := range subs {
			values, vc := h.ValuesChecked(sk)
			r := Decode(inv.category, sk, values, vc)
			r.HivePath, r.HiveAddress = id.path, id.address
			if len(r.Unread) > 0 {
				unread++
			}
			out = append(out, r)
		}
		if unread > 0 {
			ctx.AddDiagnostic("%s: key at 0x%x: %d entries with values not read: %v", Name, key.Address, unread, ErrIncomplete)
			fail(fmt.Errorf("%s: %s values: %w", Name, inv.key, ErrIncomplete))
		}
	}
	for _, k := range undecoded {
		if _, err := h.OpenKey(k); err == nil {
			ctx.AddDiagnostic("%s: hive at 0x%x: key %s present and not decoded", Name, id.address, k)
		}
	}
	if firstErr != nil && ctx.StrictMode() {
		return out, firstErr
	}
	return out, nil
}

type values struct {
	list     []registryhive.Value
	complete bool
	unread   []string
}

func (v *values) text(name string) string {
	val, found, maybe := registryhive.FindValue(v.list, v.complete, name)
	switch {
	case found && !val.Unreadable() && !val.TypeUnreadable && (val.Type == regSZ || val.Type == regExpandSZ):
		return val.Data
	case found || maybe:
		v.unread = append(v.unread, name)
	}
	return ""
}

func (v *values) dword(name string) (uint32, bool) {
	val, found, maybe := registryhive.FindValue(v.list, v.complete, name)
	switch {
	case found && !val.Unreadable() && !val.TypeUnreadable && val.Type == regDWORD && len(val.Raw) == 4:
		return binary.LittleEndian.Uint32(val.Raw), true
	case found || maybe:
		v.unread = append(v.unread, name)
	}
	return 0, false
}

const (
	regSZ       = 1
	regExpandSZ = 2
	regDWORD    = 4
)

func Decode(c Category, sk *registryhive.KeyNode, list []registryhive.Value, complete bool) InventoryRecord {
	r := InventoryRecord{Category: c, Key: sk.Name, KeyUnreadable: sk.NameUnreadable}
	if !sk.LastWriteUnreadable {
		r.KeyLastWrite, _ = util.FiletimeToTime(sk.LastWrite)
	}
	v := &values{list: list, complete: complete}
	switch c {
	case ApplicationFile:
		r.Path, r.Name, r.FileID = v.text("LowerCaseLongPath"), v.text("Name"), v.text("FileId")
		r.ProgramID, r.Publisher = v.text("ProgramId"), v.text("Publisher")
		r.Product, r.Version, r.LinkDate = v.text("ProductName"), v.text("Version"), v.text("LinkDate")
	case Application:
		r.Name, r.Path, r.ProgramID = v.text("Name"), v.text("RootDirPath"), v.text("ProgramId")
		r.Publisher, r.Version, r.InstallDate = v.text("Publisher"), v.text("Version"), v.text("InstallDate")
	case DriverBinary:
		if strings.Contains(sk.Name, "/") {
			r.Path, r.FileID = sk.Name, v.text("DriverId")
		} else if !sk.NameUnreadable {
			r.FileID = sk.Name
		}
		r.Name, r.Publisher, r.Product = v.text("DriverName"), v.text("DriverCompany"), v.text("Product")
		r.Version, r.Service = v.text("DriverVersion"), v.text("Service")
		if stamp, ok := v.dword("DriverTimeStamp"); ok && stamp != 0 {
			r.LinkTime = time.Unix(int64(stamp), 0).UTC()
		}
	}
	r.FileIDHash = IDHash(r.FileID)
	r.Unread = v.unread
	return r
}

const (
	idPadding    = "0000"
	idHashDigits = 40
)

func IDHash(id string) string {
	if len(id) != len(idPadding)+idHashDigits || !strings.HasPrefix(id, idPadding) {
		return ""
	}
	h := id[len(idPadding):]
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return h
}
