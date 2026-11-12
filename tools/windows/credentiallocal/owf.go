package credentiallocal

import (
	"crypto/des"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

const lmMaxPassword = 14

var lmPlaintext = []byte("KGS!@#$%")

func NTOWFv1(password string) [16]byte {
	units := utf16.Encode([]rune(password))
	buf := make([]byte, 0, 2*len(units))
	for _, u := range units {
		buf = binary.LittleEndian.AppendUint16(buf, u)
	}
	return md4Sum(buf)
}

// ok is false where MS-NLMP leaves LMOWFv1 undefined: more than 14
// characters, or characters outside ASCII, whose OEM upper case the
// specification does not fix.
func LMOWFv1(password string) (h [16]byte, ok bool) {
	upper := strings.ToUpper(password)
	if len(upper) > lmMaxPassword {
		return h, false
	}
	for i := 0; i < len(upper); i++ {
		if upper[i] >= 0x80 {
			return h, false
		}
	}
	var key [lmMaxPassword]byte
	copy(key[:], upper)
	for half := 0; half < 2; half++ {
		c, err := des.NewCipher(expandDESKey(key[7*half : 7*half+7]))
		if err != nil {
			return h, false
		}
		c.Encrypt(h[8*half:], lmPlaintext)
	}
	return h, true
}
