package aes_from_specs

import "errors"

const AesCipherUnitDataSize = 16

type AesKeySize uint

const (
	AesKeySize_Aes128 AesKeySize = 16
	AesKeySize_Aes192 AesKeySize = 24
	AesKeySize_Aes256 AesKeySize = 32
)

type AesCipherType string

type AesWord [4]byte

func BytesToWords(b []byte) ([]AesWord, error) {
	if len(b)%4 != 0 {
		return nil, errors.New("number of bytes must divisible by 4")
	}
	ret := make([]AesWord, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		v := AesWord{b[i], b[i+1], b[i+2], b[i+3]}
		ret[i/4] = v
	}
	return ret, nil
}

func WordsToBytes(ws []AesWord) []byte {
	ret := make([]byte, len(ws)*4)
	for i := 0; i < len(ws); i += 1 {
		b := []byte{
			ws[i][0], ws[i][1], ws[i][2], ws[i][3],
		}
		copy(ret[i*4:(i+1)*4], b[:])
	}
	return ret
}

const (
	AesCipherType_Aes128 AesCipherType = "AesCipherType_Aes128"
	AesCipherType_Aes192 AesCipherType = "AesCipherType_Aes192"
	AesCipherType_Aes256 AesCipherType = "AesCipherType_Aes256"
)
