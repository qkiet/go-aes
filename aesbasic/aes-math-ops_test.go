package aesbasic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AddNormal(t *testing.T) {
	a := byte(0x57)
	b := byte(0x83)
	c := GF_AddByte(a, b)
	assert.Equal(t, byte(0xd4), c)
}

func Test_AddMultipleTimes(t *testing.T) {
	a := byte(0x57)
	b := byte(0xae)
	c := byte(0x07)
	d := GF_AddByte(GF_AddByte(a, b), c)
	assert.Equal(t, byte(0xfe), d)
}

func Test_MultiplyBy2(t *testing.T) {
	a := byte(0x57)
	b := GF_MultiplyBy2(a)
	assert.Equal(t, byte(0xae), b)
	a = byte(0xae)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x47), b)
	a = byte(0x47)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x8e), b)
	a = byte(0x8e)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x07), b)
	a = byte(0x07)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x0e), b)
	a = byte(0x0e)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x1c), b)
	a = byte(0x1c)
	b = GF_MultiplyBy2(a)
	assert.Equal(t, byte(0x38), b)
}

func Test_MultiplySimple(t *testing.T) {
	a := byte(0x57)
	b := byte(0x1)
	c := GF_Multiply(a, b)
	assert.Equal(t, byte(0x57), c)
	b = byte(0x2)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0xae), c)
	b = byte(0x4)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x47), c)
	b = byte(0x8)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x8e), c)
	b = byte(0x10)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x07), c)
	b = byte(0x20)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x0e), c)
	b = byte(0x40)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x1c), c)
	b = byte(0x80)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x38), c)
	b = byte(0x13)
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0xfe), c)
	a = 0x53
	b = 0xca
	c = GF_Multiply(a, b)
	assert.Equal(t, byte(0x01), c)
}
