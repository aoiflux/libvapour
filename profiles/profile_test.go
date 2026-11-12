package profiles

import "testing"

func TestEachProfileNamesItsSystem(t *testing.T) {
	for _, tc := range []struct {
		p        Profile
		name, os string
	}{
		{WindowsX64Profile{}, "windows-x64", "windows"},
		{LinuxX64Profile{}, "linux-x64", "linux"},
	} {
		if tc.p.Name() != tc.name || tc.p.OS() != tc.os || tc.p.PointerSize() != 8 {
			t.Errorf("%T is %q, %q, %d; want %q, %q, 8", tc.p, tc.p.Name(), tc.p.OS(), tc.p.PointerSize(), tc.name, tc.os)
		}
	}
}
