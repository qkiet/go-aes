package aes_from_specs

import (
	"golang.org/x/exp/slices"
)

// type GFMultiplyAlgo string

// const GFMultiplyAlgo_LongDivision GFMultiplyAlgo = "GFMultiplyAlgo_LongDivision"

const GF_FixedPoly = 0x11b

// GF in here stand for Galois Field. Refer more in Advanced Encryption Standard (AES)
func GF_AddByte(a, b byte) byte {
	return a ^ b
}

func GF_AddWord(a, b AesWord) AesWord {
	return AesWord{
		GF_AddByte(a[0], b[0]), GF_AddByte(a[1], b[1]),
		GF_AddByte(a[2], b[2]), GF_AddByte(a[3], b[3]),
	}
}

func getSetBitPositions(a int) []int {
	b := a
	res := make([]int, 0)
	i := 0
	for b > 0 {
		if b&1 == 1 {
			res = append(res, i)
		}
		b = b >> 1
		i++
	}
	return res
}

func GF_MultiplyBy2(a byte) byte {
	if a&(0x80) != 0 {
		return GF_AddByte(a<<1, 0x1b)
	}
	return a << 1
}

func GF_Multiply(a, b byte) byte {
	pos := getSetBitPositions(int(b))
	t := a
	var res byte
	for i := 0; i <= int(pos[len(pos)-1]); i++ {
		if slices.Contains(pos, i) {
			res = GF_AddByte(res, t)
		}
		t = GF_MultiplyBy2(t)

	}
	return res
}
