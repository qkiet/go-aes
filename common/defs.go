package common

import (
	"errors"
	"fmt"
)

const AesCipherUnitDataSize = 16

type AesKeySize uint

const (
	AesKeySize_Aes128 AesKeySize = 16
	AesKeySize_Aes192 AesKeySize = 24
	AesKeySize_Aes256 AesKeySize = 32
)

const (
	Aes128_NumRound = 10
	Aes192_NumRound = 12
	Aes256_NumRound = 14
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

type AesState [4][4]byte

func BytesToAesState(b []byte) (AesState, error) {
	if len(b) != AesCipherUnitDataSize {
		return AesState{}, fmt.Errorf("number of bytes must be 16 but received %d", len(b))
	}
	return AesState{
		{b[0], b[4], b[8], b[12]},
		{b[1], b[5], b[9], b[13]},
		{b[2], b[6], b[10], b[14]},
		{b[3], b[7], b[11], b[15]},
	}, nil
}

func WordsToAesState(ws []AesWord) (AesState, error) {
	if len(ws) != 4 {
		return AesState{}, errors.New("number of words must be 4")
	}
	return AesState{
		{ws[0][0], ws[1][0], ws[2][0], ws[3][0]},
		{ws[0][1], ws[1][1], ws[2][1], ws[3][1]},
		{ws[0][2], ws[1][2], ws[2][2], ws[3][2]},
		{ws[0][3], ws[1][3], ws[2][3], ws[3][3]},
	}, nil
}

func AesStateToBytes(s AesState) []byte {
	return []byte{
		s[0][0], s[1][0], s[2][0], s[3][0],
		s[0][1], s[1][1], s[2][1], s[3][1],
		s[0][2], s[1][2], s[2][2], s[3][2],
		s[0][3], s[1][3], s[2][3], s[3][3],
	}
}

const (
	AesCipherType_Aes128 AesCipherType = "AesCipherType_Aes128"
	AesCipherType_Aes192 AesCipherType = "AesCipherType_Aes192"
	AesCipherType_Aes256 AesCipherType = "AesCipherType_Aes256"
)

type Aes128Key [16]byte

func BytesToAes128Key(b []byte) (Aes128Key, error) {
	if len(b) != int(AesKeySize_Aes128) {
		return Aes128Key{}, errors.New("wrong input byte length")
	}
	return Aes128Key{
		b[0], b[1], b[2], b[3],
		b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11],
		b[12], b[13], b[14], b[15],
	}, nil
}

func Aes128KeyToBytes(k Aes128Key) []byte {
	return []byte{
		k[0], k[1], k[2], k[3],
		k[4], k[5], k[6], k[7],
		k[8], k[9], k[10], k[11],
		k[12], k[13], k[14], k[15],
	}
}
