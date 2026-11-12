package linuxobj

import (
	"math"
	"math/big"
	"testing"
)

func FuzzTimespecNanoseconds(f *testing.F) {
	f.Add(int64(0), int64(0))
	f.Add(int64(ktimeSecMax), int64(999999999))
	f.Add(int64(-ktimeSecMax), int64(0))
	f.Add(int64(1), int64(1e9))
	f.Add(int64(math.MaxInt64), int64(-1))
	f.Fuzz(func(t *testing.T, sec, nsec int64) {
		got, err := timespecNanoseconds(sec, nsec)
		exact := new(big.Int).Mul(big.NewInt(sec), big.NewInt(nsecPerSec))
		exact.Add(exact, big.NewInt(nsec))
		valid := nsec >= 0 && nsec < nsecPerSec && sec <= ktimeSecMax && sec >= -ktimeSecMax && exact.IsInt64()
		if valid != (err == nil) {
			t.Fatalf("%d s %d ns: %v, want valid %t", sec, nsec, err, valid)
		}
		if err == nil && got != exact.Int64() {
			t.Fatalf("%d s %d ns: %d, want %s", sec, nsec, got, exact)
		}
	})
}

func FuzzOffsetArithmetic(f *testing.F) {
	f.Add(int64(math.MaxInt64), int64(-1))
	f.Add(int64(math.MinInt64), int64(1))
	f.Fuzz(func(t *testing.T, a, b int64) {
		d, ok := subtract(a, b)
		exact := new(big.Int).Sub(big.NewInt(a), big.NewInt(b))
		if ok != exact.IsInt64() || (ok && d != exact.Int64()) {
			t.Fatalf("%d - %d: %d %t", a, b, d, ok)
		}
		s, ok := add(a, b)
		exact = new(big.Int).Add(big.NewInt(a), big.NewInt(b))
		if ok != exact.IsInt64() || (ok && s != exact.Int64()) {
			t.Fatalf("%d + %d: %d %t", a, b, s, ok)
		}
	})
}
