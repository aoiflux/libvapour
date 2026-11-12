package credentiallocal

import (
	"encoding/binary"
	"math/bits"
)

const (
	md4Round2Add = 0x5A827999
	md4Round3Add = 0x6ED9EBA1
)

var (
	md4Round1Shift = [4]int{3, 7, 11, 19}
	md4Round2Shift = [4]int{3, 5, 9, 13}
	md4Round3Shift = [4]int{3, 9, 11, 15}
	md4Round3Order = [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
)

func md4Sum(msg []byte) [16]byte {
	padded := make([]byte, 0, len(msg)+72)
	padded = append(padded, msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.LittleEndian.AppendUint64(padded, uint64(len(msg))*8)

	state := [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	var x [16]uint32
	for block := 0; block < len(padded); block += 64 {
		for j := range x {
			x[j] = binary.LittleEndian.Uint32(padded[block+4*j:])
		}
		r := state
		// Each step updates the word at position (4 - step%4) % 4 of A, B,
		// C, D, which is RFC 1320's ABCD, DABC, CDAB, BCDA rotation.
		step := func(i int, f uint32, add uint32, k, s int) {
			a := (4 - i%4) % 4
			r[a] = bits.RotateLeft32(r[a]+f+x[k]+add, s)
		}
		for i := 0; i < 16; i++ {
			b, c, d := r[(5-i%4)%4], r[(6-i%4)%4], r[(7-i%4)%4]
			step(i, (b&c)|(^b&d), 0, i, md4Round1Shift[i%4])
		}
		for i := 0; i < 16; i++ {
			b, c, d := r[(5-i%4)%4], r[(6-i%4)%4], r[(7-i%4)%4]
			step(i, (b&c)|(b&d)|(c&d), md4Round2Add, (i%4)*4+i/4, md4Round2Shift[i%4])
		}
		for i := 0; i < 16; i++ {
			b, c, d := r[(5-i%4)%4], r[(6-i%4)%4], r[(7-i%4)%4]
			step(i, b^c^d, md4Round3Add, md4Round3Order[i], md4Round3Shift[i%4])
		}
		for j := range state {
			state[j] += r[j]
		}
	}
	var out [16]byte
	for j, w := range state {
		binary.LittleEndian.PutUint32(out[4*j:], w)
	}
	return out
}
