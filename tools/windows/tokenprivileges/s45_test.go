package tokenprivileges

import (
	"errors"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/tokensids"
)

func fixture(t *testing.T, pids ...uint64) (*testsupport.ProcessFixture, tools.Context, *[]string) {
	t.Helper()
	procs := make([]testsupport.FixtureProcess, len(pids))
	for i, pid := range pids {
		procs[i] = testsupport.FixtureProcess{PID: pid, Name: "p.exe", NoPeb: true}
	}
	f := testsupport.BuildProcessFixture(procs)
	testsupport.S45AddTokenTypes(f.Table)
	ctx := f.Context()
	diags := &[]string{}
	ctx.Options["diagnostics"] = diags
	return f, ctx, diags
}

func token(present, enabled, byDefault uint64) testsupport.S45Token {
	return testsupport.S45Token{
		Groups:  []testsupport.S45SID{{Bytes: testsupport.S45SIDBytes(5, 18)}},
		Present: present, Enabled: enabled, EnabledByDefault: byDefault,
	}
}

func TestEveryBitSetInAnyMaskIsOneRowInLUIDOrder(t *testing.T) {
	f, ctx, _ := fixture(t, 4)
	const (
		debug   = uint64(1) << 20
		notify  = uint64(1) << 23
		backup  = uint64(1) << 17
		unknown = uint64(1) << 50
	)
	tokVA := f.WriteS45Token(4, token(debug|notify|unknown, notify, notify|backup))
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		luid                        uint32
		constant                    string
		present, enabled, byDefault bool
	}{
		{17, "SE_BACKUP_NAME", false, false, true},
		{20, "SE_DEBUG_NAME", true, false, false},
		{23, "SE_CHANGE_NOTIFY_NAME", true, true, true},
		{50, "", true, false, false},
	}
	if len(rows) != len(want) {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.LUID != w.luid || r.Constant != w.constant || r.Present != w.present || r.Enabled != w.enabled ||
			r.EnabledByDefault != w.byDefault || r.TokenAddress != tokVA || r.PID != 4 || r.Failure != "" {
			t.Errorf("row %d: %+v, want %+v", i, r, w)
		}
	}
	if rows[2].Privilege != "SeChangeNotifyPrivilege" || rows[2].UserRight != "Bypass traverse checking" {
		t.Errorf("names %+v", rows[2])
	}
	if rows[3].Privilege != "" || rows[3].UserRight != "" {
		t.Errorf("an undocumented bit is named: %+v", rows[3])
	}
}

func TestATokenThatFailsItsChecksIsOneFailureRow(t *testing.T) {
	f, ctx, diags := fixture(t, 4, 8)
	f.WriteS45Token(4, testsupport.S45Token{Present: 1 << 23})
	f.WriteS45Token(8, token(1<<23, 1<<23, 1<<23))
	rows, err := Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].PID != 4 || rows[0].Failure == "" || rows[0].Constant != "" || rows[1].PID != 8 || rows[1].Failure != "" {
		t.Fatalf("rows %+v", rows)
	}
	if !strings.Contains(strings.Join(*diags, "\n"), "not listed") {
		t.Errorf("diagnostics %v", *diags)
	}
	ctx.Options["strict"] = true
	if _, err := Run(ctx); !errors.Is(err, tokensids.ErrNoTokenUser) {
		t.Errorf("strict: %v", err)
	}
}

func TestATableWithoutThePrivilegeMasksIsRefused(t *testing.T) {
	f, ctx, _ := fixture(t, 4)
	f.Table.AddStruct(mustStruct(t, f, "_SEP_TOKEN_PRIVILEGES", "Enabled"))
	if _, err := Run(ctx); !errors.Is(err, ErrLayout) {
		t.Errorf("error %v", err)
	}
}

func TestThePIDOptionSelectsTheProcessesListed(t *testing.T) {
	f, ctx, _ := fixture(t, 4, 8)
	f.WriteS45Token(4, token(1<<23, 0, 0))
	f.WriteS45Token(8, token(1<<23, 0, 0))
	ctx.Options["pid"] = uint64(8)
	rows, err := Run(ctx)
	if err != nil || len(rows) != 1 || rows[0].PID != 8 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}

func TestEveryDocumentedLUIDIsUniqueByNameAndInTheMasks(t *testing.T) {
	seen := map[string]uint32{}
	for luid, d := range privilegeByLUID {
		if luid >= maskBits || d.constant == "" || d.userRight == "" || !strings.HasPrefix(d.privilege, "Se") || !strings.HasSuffix(d.privilege, "Privilege") {
			t.Errorf("%d: %+v", luid, d)
		}
		if other, dup := seen[d.privilege]; dup {
			t.Errorf("%s at %d and %d", d.privilege, luid, other)
		}
		seen[d.privilege] = luid
	}
	if len(privilegeByLUID) != 35 {
		t.Errorf("%d documented privileges, want 35 (LUIDs 2 to 36)", len(privilegeByLUID))
	}
}

func mustStruct(t *testing.T, f *testsupport.ProcessFixture, name, drop string) (out symbols.StructType) {
	t.Helper()
	s, err := f.Table.Struct(name)
	if err != nil {
		t.Fatal(err)
	}
	out = s
	out.Fields = nil
	for _, fl := range s.Fields {
		if fl.Name != drop {
			out.Fields = append(out.Fields, fl)
		}
	}
	return out
}

func FuzzMaskExpansion(f *testing.F) {
	f.Add(uint64(1<<23), uint64(1<<23), uint64(0))
	f.Add(^uint64(0), uint64(0), ^uint64(0))
	f.Fuzz(func(t *testing.T, present, enabled, byDefault uint64) {
		rows := expand(TokenPrivilege{}, present, enabled, byDefault)
		var any uint64
		last := -1
		for _, r := range rows {
			if int(r.LUID) <= last {
				t.Fatalf("LUID %d after %d", r.LUID, last)
			}
			last = int(r.LUID)
			any |= 1 << r.LUID
		}
		if any != present|enabled|byDefault {
			t.Fatalf("rows cover 0x%x, masks 0x%x", any, present|enabled|byDefault)
		}
	})
}
