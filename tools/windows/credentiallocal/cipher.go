package credentiallocal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"errors"
	"math/bits"
)

var ErrCipherInput = errors.New("credentiallocal: ciphertext is not a whole number of blocks")

func expandDESKey(in []byte) []byte {
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = (in[0]&0x01)<<6 | in[1]>>2
	out[2] = (in[1]&0x03)<<5 | in[2]>>3
	out[3] = (in[2]&0x07)<<4 | in[3]>>4
	out[4] = (in[3]&0x0F)<<3 | in[4]>>5
	out[5] = (in[4]&0x1F)<<2 | in[5]>>6
	out[6] = (in[5]&0x3F)<<1 | in[6]>>7
	out[7] = in[6] & 0x7F
	for i := range out {
		out[i] <<= 1
		if bits.OnesCount8(out[i])%2 == 0 {
			out[i] |= 1
		}
	}
	return out
}

func ridDESKeys(rid uint32) (key1, key2 []byte) {
	var i [4]byte
	binary.LittleEndian.PutUint32(i[:], rid)
	key1 = []byte{i[0], i[1], i[2], i[3], i[0], i[1], i[2]}
	key2 = []byte{i[3], i[0], i[1], i[2], i[3], i[0], i[1]}
	return key1, key2
}

func hashUnderRID(enc []byte, rid uint32, decrypt bool) [16]byte {
	var out [16]byte
	key1, key2 := ridDESKeys(rid)
	for half, key := range [2][]byte{key1, key2} {
		c, _ := des.NewCipher(expandDESKey(key))
		if decrypt {
			c.Decrypt(out[8*half:], enc[8*half:8*half+8])
		} else {
			c.Encrypt(out[8*half:], enc[8*half:8*half+8])
		}
	}
	return out
}

func AESCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil, ErrCipherInput
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func aesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil, ErrCipherInput
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}
