package tracingftrace

import "testing"

// The image is untrusted: whatever an ops, its hashes, their buckets and
// entries hold, the tool ends, and only a function scope names a hooked
// address.
func FuzzHashReader(f *testing.F) {
	seed := newFixture(true)
	standard(seed)
	ops, _ := seed.Mem.ReadAt(seed.ops[0], opsSize)
	hash, _ := seed.Mem.ReadAt(seed.ops[0]+0x1800, 0x800)
	f.Add(ops, hash)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, opsBytes, hashBytes []byte) {
		fx := newFixture(true)
		standard(fx)
		fx.Mem.Write(fx.ops[0], opsBytes)
		fx.Mem.Write(fx.ops[0]+0x1800, hashBytes)
		rows, _, err := fx.run(t, map[string]any{OptionShowFlags: true})
		if err != nil {
			return
		}
		for _, r := range rows {
			if r.Scope != ScopeFunction && r.HookedAddress != 0 {
				t.Fatalf("scope %s with a hooked address: %+v", r.Scope, r)
			}
		}
	})
}
