package credentiallocal

import (
	"bytes"
	"testing"

	"github.com/aoiflux/libvapour/tools"
	"github.com/aoiflux/libvapour/tools/windows/registryhive"
	"github.com/aoiflux/libvapour/tools/windows/registryhive/registrytest"
)

func diagCtx() (tools.Context, *[]string) {
	diags := &[]string{}
	return tools.Context{Options: map[string]any{diagnosticsKey: diags}}, diags
}

func samWithAccounts(domainKey []byte, accts map[uint32]string) *registrytest.FakeHive {
	h := registrytest.NewFakeHive("SAM")
	users := h.Path(`SAM\Domains\Account\Users`)
	for rid, name := range accts {
		key := h.Key(users, ridHex(rid))
		v := buildVFor(domainKey, name, rid)
		h.Values[key] = []registryhive.Value{{Name: "V", Raw: v, Length: uint32(len(v))}}
	}
	return h
}

func ridHex(rid uint32) string {
	const digits = "0123456789ABCDEF"
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for i := 7; i >= 0; i-- {
		b[i] = digits[rid&0xF]
		rid >>= 4
	}
	return string(b)
}

func buildVFor(domainKey []byte, name string, rid uint32) []byte {
	nt := NTOWFv1("fixture-" + name)
	iv := bytes.Repeat([]byte{0x33}, 16)
	wrapped := hashUnderRID(nt[:], rid, false)
	cipher, _ := aesCBCEncrypt(domainKey, iv, padTo16(wrapped[:]))
	rec := make([]byte, recordAESMinLen)
	rec[recordRevisionOffset] = byte(revisionAES)
	rec[recordLengthOffset] = 16
	copy(rec[recordIVOffset:], iv)
	copy(rec[recordCipherOffset:], cipher)
	return buildV(nameBytes(name), rec)
}

func TestAccountsEnumeratesEveryRIDInOrder(t *testing.T) {
	domainKey := bytes.Repeat([]byte{0x42}, 16)
	ctx, diags := diagCtx()
	h := samWithAccounts(domainKey, map[uint32]string{500: "Administrator", 1001: "worker", 501: "Guest"})
	rows := accounts(ctx, h, domainKey)
	if len(rows) != 3 {
		t.Fatalf("rows = %d", len(rows))
	}
	if rows[0].RID != 500 || rows[1].RID != 501 || rows[2].RID != 1001 {
		t.Errorf("order = %d %d %d", rows[0].RID, rows[1].RID, rows[2].RID)
	}
	if rows[0].User != "Administrator" {
		t.Errorf("name = %q", rows[0].User)
	}
	if rows[0].NTHash == "" {
		t.Error("no NT hash recovered")
	}
	if len(*diags) != 0 {
		t.Errorf("unexpected diagnostics: %v", *diags)
	}
}

func TestAccountsFlagsAnUnreadableV(t *testing.T) {
	ctx, diags := diagCtx()
	h := registrytest.NewFakeHive("SAM")
	users := h.Path(`SAM\Domains\Account\Users`)
	key := h.Key(users, ridHex(500))
	h.Values[key] = []registryhive.Value{{Name: "V", Length: 400}} // Raw shorter than Length
	rows := accounts(ctx, h, bytes.Repeat([]byte{1}, 16))
	if len(rows) != 1 || !rows[0].NTUnreadable || !rows[0].LMUnreadable {
		t.Fatalf("rows = %+v", rows)
	}
	if len(*diags) == 0 {
		t.Error("no diagnostic raised")
	}
}
