package tokensids

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aoiflux/libvapour/internal/testsupport"
	"github.com/aoiflux/libvapour/profiles"
	"github.com/aoiflux/libvapour/symbols"
	"github.com/aoiflux/libvapour/tools"
)

var (
	sidSystem    = testsupport.S45SIDBytes(5, 18)
	sidAdmins    = testsupport.S45SIDBytes(5, 32, 544)
	sidEveryone  = testsupport.S45SIDBytes(1, 0)
	sidLogon     = testsupport.S45SIDBytes(5, 5, 0, 999)
	sidSystemIL  = testsupport.S45SIDBytes(16, 16384)
	sidWrite     = testsupport.S45SIDBytes(5, 33)
	sidCapabilty = testsupport.S45SIDBytes(15, 3, 1)
)

func fullToken() testsupport.S45Token {
	return testsupport.S45Token{
		Groups: []testsupport.S45SID{
			{Bytes: sidSystem},
			{Bytes: sidAdmins, Attributes: 0xe},
			{Bytes: sidEveryone, Attributes: 0x7},
			{Bytes: sidLogon, Attributes: 0xc0000007},
			{Bytes: sidSystemIL, Attributes: 0x60},
		},
		Restricted:   []testsupport.S45SID{{Bytes: sidWrite, Attributes: 0x7}},
		Capabilities: []testsupport.S45SID{{Bytes: sidCapabilty, Attributes: 0x4}},
		RefCount:     0xb,
	}
}

type fixture struct {
	f     *testsupport.ProcessFixture
	diags []string
}

func newFixture(pids ...uint64) *fixture {
	procs := make([]testsupport.FixtureProcess, len(pids))
	for i, pid := range pids {
		procs[i] = testsupport.FixtureProcess{PID: pid, Name: "p" + strconv.FormatUint(pid, 10) + ".exe", NoPeb: true}
	}
	f := testsupport.BuildProcessFixture(procs)
	testsupport.S45AddTokenTypes(f.Table)
	return &fixture{f: f}
}

func (x *fixture) ctx() tools.Context {
	ctx := x.f.Context()
	ctx.Options["diagnostics"] = &x.diags
	return ctx
}

func (x *fixture) run(t *testing.T, ctx tools.Context) []TokenSID {
	t.Helper()
	rows, err := Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return rows
}

func identifiers(rows []TokenSID) []string {
	var out []string
	for _, r := range rows {
		out = append(out, string(r.Array)+":"+strconv.Itoa(r.Index)+":"+r.Identifier)
	}
	return out
}

func TestEveryArrayOfATokenIsListedInOrderWithItsAttributesAndNames(t *testing.T) {
	x := newFixture(4)
	tokVA := x.f.WriteS45Token(4, fullToken())
	ctx := x.ctx()
	rows := x.run(t, ctx)
	want := []string{
		"UserAndGroups:0:S-1-5-18", "UserAndGroups:1:S-1-5-32-544", "UserAndGroups:2:S-1-1-0",
		"UserAndGroups:3:S-1-5-5-0-999", "UserAndGroups:4:S-1-16-16384",
		"RestrictedSids:0:S-1-5-33", "Capabilities:0:S-1-15-3-1",
	}
	if got := identifiers(rows); !slices.Equal(got, want) {
		t.Fatalf("rows %v, want %v", got, want)
	}
	ep, _ := x.f.EPROCESS(4)
	for i, r := range rows {
		if r.PID != 4 || r.Process != "p4.exe" || r.ProcessAddress != ep || r.TokenAddress != tokVA || r.Failure != "" {
			t.Errorf("row %d: %+v", i, r)
		}
		if r.TokenUser != (i == 0) {
			t.Errorf("row %d: token user %v", i, r.TokenUser)
		}
	}
	names := map[string]string{"S-1-5-18": "LOCAL_SYSTEM", "S-1-5-32-544": "BUILTIN_ADMINISTRATORS",
		"S-1-1-0": "EVERYONE", "S-1-5-5-0-999": "LOGON_ID", "S-1-16-16384": "ML_SYSTEM", "S-1-5-33": "WRITE_RESTRICTED_CODE"}
	for _, r := range rows {
		if n, ok := names[r.Identifier]; ok && (r.Principal != n || r.PrincipalFrom != FromDocumentedSID) {
			t.Errorf("%s: named %q from %q, want %q", r.Identifier, r.Principal, r.PrincipalFrom, n)
		}
	}
	capability := rows[len(rows)-1]
	if capability.Principal != "" || !capability.NamesIncomplete {
		t.Errorf("a capability no source names, with no registry read, is unnamed and marked: %+v", capability)
	}
	if got := rows[3].AttributeNames; !slices.Equal(got, []string{"SE_GROUP_MANDATORY", "SE_GROUP_ENABLED_BY_DEFAULT", "SE_GROUP_ENABLED", "SE_GROUP_LOGON_ID"}) {
		t.Errorf("logon attributes %v", got)
	}
	if rows[1].Attributes != 0xe {
		t.Errorf("attributes 0x%x", rows[1].Attributes)
	}
	if !slices.ContainsFunc(x.diags, func(d string) bool { return strings.Contains(d, "names incomplete") }) {
		t.Errorf("no diagnostic for the absent hives: %v", x.diags)
	}
}

func tokenRows(t *testing.T, x *fixture, ctx tools.Context) []TokenSID {
	t.Helper()
	rows := x.run(t, ctx)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	return rows
}

func TestEachTokenRuleRefusesTheTokenOnItsOwn(t *testing.T) {
	cases := []struct {
		name  string
		setup func(x *fixture)
		limit int
		want  error
	}{
		{"null token", func(x *fixture) { x.f.S45SetTokenPointer(4, 0x7) }, 0, ErrNoToken},
		{"user space", func(x *fixture) { x.f.S45SetTokenPointer(4, 0x10000) }, 0, ErrTokenNotSystem},
		{"unread", func(x *fixture) { x.f.S45SetTokenPointer(4, testsupport.S45UnmappedKernelAddress) }, 0, ErrTokenUnread},
		{"no user", func(x *fixture) { x.f.WriteS45Token(4, testsupport.S45Token{}) }, 0, ErrNoTokenUser},
		{"too many", func(x *fixture) { x.f.WriteS45Token(4, fullToken()) }, 4, ErrTooManySIDs},
		{"misplaced", func(x *fixture) {
			tok := fullToken()
			tok.GroupsPointer = 0xfffff80002040000
			x.f.WriteS45Token(4, tok)
		}, 0, ErrGroupsMisplaced},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newFixture(4)
			c.setup(x)
			ctx := x.ctx()
			ctx.Limits.MaxRowsPerObject = c.limit
			rows := tokenRows(t, x, ctx)
			if len(rows) != 1 || rows[0].Failure == "" || rows[0].Identifier != "" || rows[0].Array != "" {
				t.Fatalf("rows %+v, want one failure row", rows)
			}
			if _, err := reader(t, ctx).Token(mustEprocess(x, 4)); !errors.Is(err, c.want) {
				t.Errorf("error %v, want %v", err, c.want)
			}
			if len(x.diags) == 0 || !strings.Contains(strings.Join(x.diags, "\n"), "not listed") {
				t.Errorf("diagnostics %v", x.diags)
			}
		})
	}
}

func reader(t *testing.T, ctx tools.Context) TokenReader {
	t.Helper()
	r, err := NewTokenReader(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustEprocess(x *fixture, pid uint64) uint64 {
	ep, _ := x.f.EPROCESS(pid)
	return ep
}

func TestAMisplacedOrUnreachableSecondaryArrayIsDroppedAlone(t *testing.T) {
	tok := fullToken()
	tok.RestrictedPointer = 0xfffff80002041000
	tok.CapabilityPointer = 0x2000
	x := newFixture(4)
	x.f.WriteS45Token(4, tok)
	rows := x.run(t, x.ctx())
	for _, r := range rows {
		if r.Array != UserAndGroups {
			t.Errorf("row from a dropped array: %+v", r)
		}
	}
	if len(rows) != len(tok.Groups) {
		t.Errorf("%d rows, want %d", len(rows), len(tok.Groups))
	}
	joined := strings.Join(x.diags, "\n")
	if !strings.Contains(joined, "RestrictedSids not listed") || !strings.Contains(joined, "Capabilities not listed") {
		t.Errorf("diagnostics %v", x.diags)
	}
}

func TestEachSIDRuleFailsItsEntryAndTheWalkGoesOn(t *testing.T) {
	bad := []testsupport.S45SID{
		{Bytes: sidSystem},
		{Pointer: 0},
		{Pointer: 0x3000},
		{Pointer: testsupport.S45UnmappedKernelAddress},
		{Bytes: []byte{2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}},
		{Bytes: append([]byte{1, 16, 0, 0, 0, 0, 0, 5}, make([]byte, 64)...)},
		{Bytes: sidEveryone, Attributes: 0x7},
	}
	want := []error{nil, ErrSIDPointer, ErrSIDPointer, ErrSIDUnread, ErrSIDRevision, ErrSIDSubAuthorities, nil}
	x := newFixture(4)
	x.f.WriteS45Token(4, testsupport.S45Token{Groups: bad})
	ctx := x.ctx()
	rows := x.run(t, ctx)
	if len(rows) != len(bad) {
		t.Fatalf("%d rows, want %d", len(rows), len(bad))
	}
	r := reader(t, ctx)
	tok, err := r.Token(mustEprocess(x, 4))
	if err != nil {
		t.Fatal(err)
	}
	for i := range bad {
		_, err := r.entryAt(tok.Arrays[0], uint32(i))
		if want[i] == nil {
			if err != nil || rows[i].Identifier == "" {
				t.Errorf("entry %d: %v, row %+v", i, err, rows[i])
			}
			continue
		}
		if !errors.Is(err, want[i]) || rows[i].Failure == "" || rows[i].Identifier != "" {
			t.Errorf("entry %d: %v, want %v; row %+v", i, err, want[i], rows[i])
		}
	}
	if got := strings.Count(strings.Join(x.diags, "\n"), "sid at 0x"); got != 5 {
		t.Errorf("%d sid diagnostics, want 5: %v", got, x.diags)
	}
}

func TestStrictModeStopsAtTheFirstFailureWithTheRowsSoFar(t *testing.T) {
	x := newFixture(4, 8)
	x.f.WriteS45Token(4, fullToken())
	x.f.S45SetTokenPointer(8, 0)
	ctx := x.ctx()
	ctx.Options["strict"] = true
	rows, err := Run(ctx)
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("error %v", err)
	}
	if len(rows) != len(fullToken().Groups)+2+1 || rows[0].PID != 4 || rows[len(rows)-1].PID != 8 || rows[len(rows)-1].Failure == "" {
		t.Errorf("rows %v", identifiers(rows))
	}
}

func TestThePIDOptionSelectsTheProcessesListed(t *testing.T) {
	x := newFixture(4, 8, 12)
	for _, pid := range []uint64{4, 8, 12} {
		x.f.WriteS45Token(pid, fullToken())
	}
	ctx := x.ctx()
	ctx.Options["pid"] = []uint64{8}
	for _, r := range x.run(t, ctx) {
		if r.PID != 8 {
			t.Fatalf("pid %d listed", r.PID)
		}
	}
}

func TestATableWithoutATokenMemberOrAWindowsProfileIsRefused(t *testing.T) {
	x := newFixture(4)
	ctx := x.ctx()
	ctx.Profile = profiles.LinuxX64Profile{}
	if _, err := NewTokenReader(ctx); !errors.Is(err, ErrNotWindows) {
		t.Errorf("linux profile: %v", err)
	}
	bare := &fixture{f: testsupport.BuildProcessFixture([]testsupport.FixtureProcess{{PID: 4, Name: "p4.exe", NoPeb: true}})}
	if _, err := Run(bare.ctx()); !errors.Is(err, ErrLayout) {
		t.Errorf("no token types: %v", err)
	}
}

func TestTheSIDStringFormFollowsTheDocumentedSyntax(t *testing.T) {
	cases := []struct {
		b    []byte
		want string
	}{
		{testsupport.S45SIDBytes(5), "S-1-5"},
		{testsupport.S45SIDBytes(5, 21, 1, 2, 3, 1001), "S-1-5-21-1-2-3-1001"},
		{testsupport.S45SIDBytes(0xffffffff, 7), "S-1-4294967295-7"},
		{testsupport.S45SIDBytes(1<<32, 7), "S-1-0x000100000000-7"},
		{testsupport.S45SIDBytes(0x123456789abc, 4294967295), "S-1-0x123456789ABC-4294967295"},
	}
	for _, c := range cases {
		s, err := decodeSID(c.b)
		if err != nil || s.String() != c.want {
			t.Errorf("%x: %q %v, want %q", c.b, s.String(), err, c.want)
		}
		if !slices.Equal(s.bytes(), c.b) {
			t.Errorf("%s does not encode back", c.want)
		}
	}
	if _, err := decodeSID([]byte{1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}); !errors.Is(err, ErrSIDUnread) {
		t.Errorf("short sub-authorities: %v", err)
	}
}

func TestAttributeNamesFollowTheDocumentedBitsAndShowTheRest(t *testing.T) {
	if got := attributeNames(0x40000020 | 0x100); !slices.Equal(got, []string{"SE_GROUP_INTEGRITY", "0x40000100"}) {
		t.Errorf("one logon bit and an undocumented bit: %v", got)
	}
	if got := attributeNames(0); got != nil {
		t.Errorf("no bits: %v", got)
	}
}

func parseIdentifier(t *testing.T, id string) sid {
	t.Helper()
	parts := strings.Split(id, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" {
		t.Fatalf("%q is not a sid string", id)
	}
	a, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		t.Fatalf("%q: %v", id, err)
	}
	s := sid{authority: a}
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		s.sub = append(s.sub, uint32(v))
	}
	return s
}

func TestEveryDocumentedSIDIsCanonicalAndNamedOnce(t *testing.T) {
	for _, table := range []map[string]string{documentedSIDs, win32SIDs} {
		for id, name := range table {
			if s := parseIdentifier(t, id); s.String() != id {
				t.Errorf("%q formats as %q", id, s.String())
			}
			if name == "" {
				t.Errorf("%q has no name", id)
			}
		}
	}
	for id := range win32SIDs {
		if _, dup := documentedSIDs[id]; dup {
			t.Errorf("%q is in both tables", id)
		}
	}
}

func TestServiceSIDsDeriveAsMicrosoftsExamples(t *testing.T) {
	for name, want := range map[string]string{
		"ALG":            "S-1-5-80-2387347252-3645287876-2469496166-3824418187-3586569773",
		"dps":            "S-1-5-80-2970612574-78537857-698502321-558674196-1451644582",
		"WdiServiceHost": "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
	} {
		if got := sidOfServiceName(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestNamesComeFromTheFirstSourceThatHasThem(t *testing.T) {
	user := "S-1-5-21-1-2-3-500"
	svc := sidOfServiceName("Dhcp")
	p := principals{
		services: nameSource{names: map[string]string{svc: `NT SERVICE\Dhcp`, "S-1-5-18": "x"}, complete: true},
		accounts: nameSource{names: map[string]string{user: "Administrator", svc: "y", "S-1-5-32-583": "Device Owners"}, complete: true},
		profiles: nameSource{names: map[string]string{user: "admin.000", "S-1-5-21-1-2-3-1001": "mew"}, complete: true},
	}
	cases := []struct {
		id   string
		name string
		from PrincipalSource
	}{
		{"S-1-5-18", "LOCAL_SYSTEM", FromDocumentedSID},
		{"S-1-5-32-583", "DOMAIN_ALIAS_RID_DEVICE_OWNERS", FromDocumentedSID},
		{"S-1-5-83-1-1-2-3-4", remoteMachineName, FromDocumentedSID},
		{svc, `NT SERVICE\Dhcp`, FromServiceName},
		{user, "Administrator", FromSAMAccount},
		{"S-1-5-21-1-2-3-1001", "mew", FromProfileFolder},
		{"S-1-5-21-9-9-9-513", "DOMAIN_USERS", FromDomainRID},
		{"S-1-5-21-9-9-9-1001", "", ""},
	}
	for _, c := range cases {
		got := p.name(parseIdentifier(t, c.id))
		if got.name != c.name || got.from != c.from || got.incomplete {
			t.Errorf("%s: %+v, want %q from %q", c.id, got, c.name, c.from)
		}
	}
}

func TestAnUnnamedSIDIsMarkedOnlyWhereAnIncompleteSourceCoversIt(t *testing.T) {
	whole := nameSource{names: map[string]string{}, complete: true}
	part := nameSource{names: map[string]string{}}
	cases := []struct {
		p    principals
		id   string
		want bool
	}{
		{principals{services: part, accounts: whole, profiles: whole}, "S-1-5-80-1-2-3-4-5", true},
		{principals{services: part, accounts: whole, profiles: whole}, "S-1-5-21-1-2-3-1001", false},
		{principals{services: whole, accounts: part, profiles: whole}, "S-1-5-21-1-2-3-1001", true},
		{principals{services: whole, accounts: part, profiles: whole}, "S-1-5-32-999", true},
		{principals{services: whole, accounts: part, profiles: whole}, "S-1-15-3-1", false},
		{principals{services: whole, accounts: whole, profiles: part}, "S-1-15-3-1", true},
	}
	for _, c := range cases {
		if got := c.p.name(parseIdentifier(t, c.id)).incomplete; got != c.want {
			t.Errorf("%s: incomplete %v, want %v", c.id, got, c.want)
		}
	}
}

func fuzzTable() *symbols.Table {
	t := symbols.NewTable("fuzz", 8)
	t.AddStruct(symbols.StructType{Name: "_EPROCESS", Size: 0x800})
	testsupport.S45AddTokenTypes(t)
	return t
}
