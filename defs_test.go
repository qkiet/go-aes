package aes_from_specs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BytesToWords(t *testing.T) {
	input0 := []byte{0x00, 0x01, 0x02, 0x03}
	expect0 := []AesWord{
		{0x00, 0x01, 0x02, 0x03},
	}
	cal0, err := BytesToWords(input0)
	assert.NoError(t, err)
	assert.Equal(t, expect0, cal0)

	input1 := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	_, err = BytesToWords(input1)
	assert.Error(t, err)

	input2 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	expect2 := []AesWord{
		{0x00, 0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07},
	}
	cal2, err := BytesToWords(input2)
	assert.NoError(t, err)
	assert.Equal(t, expect2, cal2)
}

func Test_WordsToBytes(t *testing.T) {
	input0 := []AesWord{
		{0x00, 0x01, 0x02, 0x03},
	}
	expect0 := []byte{
		0x00, 0x01, 0x02, 0x03,
	}
	cal0 := WordsToBytes(input0)
	assert.Equal(t, expect0, cal0)

	input1 := []AesWord{
		{0x00, 0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06, 0x07}}
	expect1 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	cal1 := WordsToBytes(input1)
	assert.Equal(t, expect1, cal1)
}
