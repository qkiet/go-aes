package aesbasic

import (
	"errors"
	"testing"

	"github.com/qkiet/go-aes/common"
	"github.com/stretchr/testify/assert"
)

func Test_ConvertHexStringToBytes(t *testing.T) {
	var inputs = []string{
		"43c9f7e62f5d288bb27aa40ef8fe1ea8",
		"f4a70d8af877f9b02b4c40df57d45bxx",
	}
	var expected_outputs = [][]byte{
		{0x43, 0xc9, 0xf7, 0xe6, 0x2f, 0x5d, 0x28, 0x8b, 0xb2, 0x7a, 0xa4, 0x0e, 0xf8, 0xfe, 0x1e, 0xa8},
		nil,
	}
	for i, input := range inputs {
		b, err := HexStringToBytes(input)
		assert.Equal(t, expected_outputs[i], b)
		if expected_outputs[i] != nil {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}

	}
}

func convertHexStringsToBytesAndCheck(t *testing.T, s string) []byte {
	b, err := HexStringToBytes(s)
	assert.NoError(t, err)
	return b
}

func convertBytesToAesStateAndCheck(t *testing.T, s []byte) common.AesState {
	state, err := bytesToAesState(s)
	assert.NoError(t, err)
	return state
}

func bytesToAesState(b []byte) (common.AesState, error) {
	if len(b) != common.AesCipherUnitDataSize {
		return common.AesState{}, errors.New("number of bytes must be 16")
	}
	return common.AesState{
		{b[0], b[4], b[8], b[12]},
		{b[1], b[5], b[9], b[13]},
		{b[2], b[6], b[10], b[14]},
		{b[3], b[7], b[11], b[15]},
	}, nil
}

func Test_AES128KeyExpansion(t *testing.T) {
	var keys = []string{
		"2b7e151628aed2a6abf7158809cf4f3c",
	}
	var expectedOutputs = []string{
		"2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6",
	}
	for i, key := range keys {
		keyBytes := convertHexStringsToBytesAndCheck(t, key)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		expandedKey := KeyExpansion(keyBytes)
		assert.Equal(t, expectedOutputBytes, expandedKey)
	}
}

func Test_AES128AddRoundKey(t *testing.T) {
	var inputs = []string{
		"3243f6a8885a308d313198a2e0370734",
		"046681e5e0cb199a48f8d37a2806264c",
	}
	var keys = []string{
		"2b7e151628aed2a6abf7158809cf4f3c",
		"a0fafe1788542cb123a339392a6c7605",
	}
	var expectedOutputs = []string{
		"193de3bea0f4e22b9ac68d2ae9f84808",
		"a49c7ff2689f352b6b5bea43026a5049",
	}
	for i, input := range inputs {
		inputBytes := convertHexStringsToBytesAndCheck(t, input)
		inputState := convertBytesToAesStateAndCheck(t, inputBytes)
		keyBytes := convertHexStringsToBytesAndCheck(t, keys[i])
		keyState := convertBytesToAesStateAndCheck(t, keyBytes)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		expectedState := convertBytesToAesStateAndCheck(t, expectedOutputBytes)
		calculatedState := AddRoundKey(inputState, keyState)
		assert.Equal(t, expectedState, calculatedState)
	}
}

func Test_SubBytes(t *testing.T) {
	var inputs = []string{
		"193de3bea0f4e22b9ac68d2ae9f84808",
		"a49c7ff2689f352b6b5bea43026a5049",
	}
	var expectedOutputs = []string{
		"d42711aee0bf98f1b8b45de51e415230",
		"49ded28945db96f17f39871a7702533b",
	}
	for i, input := range inputs {
		inputBytes := convertHexStringsToBytesAndCheck(t, input)
		inputState := convertBytesToAesStateAndCheck(t, inputBytes)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		expectedState := convertBytesToAesStateAndCheck(t, expectedOutputBytes)
		calculatedState := SubBytes(inputState)
		assert.Equal(t, expectedState, calculatedState)
	}
}

func Test_ShiftRows(t *testing.T) {
	var inputs = []string{
		"d42711aee0bf98f1b8b45de51e415230",
		"49ded28945db96f17f39871a7702533b",
		"ac73cf7befc111df13b5d6b545235ab8",
	}
	var expectedOutputs = []string{
		"d4bf5d30e0b452aeb84111f11e2798e5",
		"49db873b453953897f02d2f177de961a",
		"acc1d6b8efb55a7b1323cfdf457311b5",
	}
	for i, input := range inputs {
		inputBytes := convertHexStringsToBytesAndCheck(t, input)
		inputState := convertBytesToAesStateAndCheck(t, inputBytes)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		expectedState := convertBytesToAesStateAndCheck(t, expectedOutputBytes)
		calculatedState := ShiftRows(inputState)
		assert.Equal(t, expectedState, calculatedState)
	}
}

func Test_MixColumns(t *testing.T) {
	var inputs = []string{
		"d4bf5d30e0b452aeb84111f11e2798e5",
		"49db873b453953897f02d2f177de961a",
		"acc1d6b8efb55a7b1323cfdf457311b5",
	}
	var expectedOutputs = []string{
		"046681e5e0cb199a48f8d37a2806264c",
		"584dcaf11b4b5aacdbe7caa81b6bb0e5",
		"75ec0993200b633353c0cf7cbb25d0dc",
	}
	for i, input := range inputs {
		inputBytes := convertHexStringsToBytesAndCheck(t, input)
		inputState := convertBytesToAesStateAndCheck(t, inputBytes)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		expectedState := convertBytesToAesStateAndCheck(t, expectedOutputBytes)
		calculatedState := MixColumns(inputState)
		assert.Equal(t, expectedState, calculatedState)
	}
}

func Test_InvOperations(t *testing.T) {
	var inputs = []string{
		"d4bf5d30e0b452aeb84111f11e2798e5",
		"49db873b453953897f02d2f177de961a",
		"acc1d6b8efb55a7b1323cfdf457311b5",
	}
	key := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	}
	for _, input := range inputs {
		inputBytes := convertHexStringsToBytesAndCheck(t, input)
		inputState := convertBytesToAesStateAndCheck(t, inputBytes)

		outputState := MixColumns(inputState)
		invOutputState := InvMixColumns(outputState)
		assert.Equal(t, inputState, invOutputState)

		outputState = SubBytes(inputState)
		invOutputState = InvSubBytes(outputState)
		assert.Equal(t, inputState, invOutputState)

		outputState = ShiftRows(inputState)
		invOutputState = InvShiftRows(outputState)
		assert.Equal(t, inputState, invOutputState)

		keyState, _ := common.BytesToAesState(key)
		outputState = AddRoundKey(inputState, keyState)
		invOutputState = AddRoundKey(outputState, keyState)
		assert.Equal(t, inputState, invOutputState)
	}
}
