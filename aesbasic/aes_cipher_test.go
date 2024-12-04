package aesbasic

import (
	"testing"

	"github.com/qkiet/go-aes/common"
	"github.com/stretchr/testify/assert"
)

func Test_AES128Cipher(t *testing.T) {
	plainText := "00000000000000000000000000000000"
	var keys = []string{
		"6c002b682483e0cabcc731c253be5674",
		"143ae8ed6555aba96110ab58893a8ae1",
		"b69418a85332240dc82492353956ae0c",
		"71b5c08a1993e1362e4d0ce9b22b78d5",
		"e234cdca2606b81f29408d5f6da21206",
		"13237c49074a3da078dc1d828bb78c6f",
		"3071a2a48fe6cbd04f1a129098e308f8",
		"90f42ec0f68385f2ffc5dfc03a654dce",
		"febd9a24d8b65c1c787d50a4ed3619a9",
	}
	var expectedOutputs = []string{
		"3580d19cff44f1014a7c966a69059de5",
		"806da864dd29d48deafbe764f8202aef",
		"a303d940ded8f0baff6f75414cac5243",
		"c2dabd117f8a3ecabfbb11d12194d9d0",
		"fff60a4740086b3b9c56195b98d91a7b",
		"8146a08e2357f0caa30ca8c94d1a0544",
		"4b98e06d356deb07ebb824e5713f7be3",
		"7a20a53d460fc9ce0423a7a0764c6cf2",
		"f4a70d8af877f9b02b4c40df57d45b17",
	}
	plainTextBytes := ConvertHexStringsToBytesAndCheck(t, plainText)
	for i, k := range keys {
		keyBytes := convertHexStringsToBytesAndCheck(t, k)
		keyAes128, err := common.BytesToAes128Key(keyBytes)
		assert.NoError(t, err)
		expectedOutputBytes := convertHexStringsToBytesAndCheck(t, expectedOutputs[i])
		calculatedBytes, err := AES128Encrypt(plainTextBytes, keyAes128)
		assert.NoError(t, err)
		assert.Equal(t, expectedOutputBytes, calculatedBytes)
		calculatedBytes, err = AES128Decrypt(expectedOutputBytes, keyAes128)
		assert.NoError(t, err)
		assert.Equal(t, plainTextBytes, calculatedBytes)
	}
}
