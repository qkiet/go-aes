package aes_from_specs

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func hexStringToBytes(s string) ([]byte, error) {
	var ret []byte
	for i := 0; i < len(s); i += 2 {
		ele := s[i : i+2]
		b, err := strconv.ParseUint(ele, 16, 8)
		if err != nil {
			return nil, errors.New("Not a hex strings")
		}
		ret = append(ret, byte(b))
	}
	return ret, nil
}

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
		b, err := hexStringToBytes(input)
		assert.Equal(t, expected_outputs[i], b)
		if expected_outputs[i] != nil {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}

	}
}

func convertHexStringsToBytesAndCheck(t *testing.T, s string) []byte {
	b, err := hexStringToBytes(s)
	assert.NoError(t, err)
	return b
}

func convertBytesToAesStateAndCheck(t *testing.T, s []byte) AesState {
	state, err := BytesToAesState(s)
	assert.NoError(t, err)
	return state
}

func Test_AES128KeyExpansion(t *testing.T) {
	var keys = []string{
		"2b7e151628aed2a6abf7158809cf4f3c",
		// "43c9f7e62f5d288bb27aa40ef8fe1ea8",
		// "f4a70d8af877f9b02b4c40df57d45b17",
		// "35870c6a57e9e92314bcb8087cde72ce",
	}
	var expectedOutputs = []string{
		"2b7e151628aed2a6abf7158809cf4f3ca0fafe1788542cb123a339392a6c7605f2c295f27a96b9435935807a7359f67f3d80477d4716fe3e1e237e446d7a883bef44a541a8525b7fb671253bdb0bad00d4d1c6f87c839d87caf2b8bc11f915bc6d88a37a110b3efddbf98641ca0093fd4e54f70e5f5fc9f384a64fb24ea6dc4fead27321b58dbad2312bf5607f8d292fac7766f319fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6",
		// "66346137306438616638373766396230759e650445fa5d6523c26a5245fb086278aecf6a3d54920f1e96f85d5b6df03f4022ba537d76285c63e0d001388d203e1595085468e320080b03f009338ed0371ce592977406b29f7f0542964c8b92a101aaa0be75ac12210aa950b74622c216d28fe7e4a723f5c5ad8aa572eba86764900aa40d372951c89aa3f4ba710b93dea0d6b9ae97ffe8660d5c1cdc7c578f02cda5cebe5a5a26d857063a042b51b506",
		// "333538373063366135376539653932332016fb7a1075cd1b2542a822407b9a1103ae797313dbb46836991c4a76e2865b9fea404b8c31f423baa8e869cc4a6e3241756300cd44972377ec7f4abba6117875f7dfeab8b348c9cf5f378374f926fbcc00d07874b398b1bbecaf32cf1589c9d5a70df2a11495431af83a71d5edb3b800ca61f1a1def4b2bb26cec36ecb7d7b0435406ea5ebb4dc1ecd7a1f700607645df0033ff81bb7e3e6d6cdfc96d0ca98",
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
		// "43c9f7e62f5d288bb27aa40ef8fe1ea8",
		// "f4a70d8af877f9b02b4c40df57d45b17",
		// "35870c6a57e9e92314bcb8087cde72ce",
	}
	var keys = []string{
		"2b7e151628aed2a6abf7158809cf4f3c",
	}
	var expectedOutputs = []string{
		"193de3bea0f4e22b9ac68d2ae9f84808",
		// "66346137306438616638373766396230759e650445fa5d6523c26a5245fb086278aecf6a3d54920f1e96f85d5b6df03f4022ba537d76285c63e0d001388d203e1595085468e320080b03f009338ed0371ce592977406b29f7f0542964c8b92a101aaa0be75ac12210aa950b74622c216d28fe7e4a723f5c5ad8aa572eba86764900aa40d372951c89aa3f4ba710b93dea0d6b9ae97ffe8660d5c1cdc7c578f02cda5cebe5a5a26d857063a042b51b506",
		// "333538373063366135376539653932332016fb7a1075cd1b2542a822407b9a1103ae797313dbb46836991c4a76e2865b9fea404b8c31f423baa8e869cc4a6e3241756300cd44972377ec7f4abba6117875f7dfeab8b348c9cf5f378374f926fbcc00d07874b398b1bbecaf32cf1589c9d5a70df2a11495431af83a71d5edb3b800ca61f1a1def4b2bb26cec36ecb7d7b0435406ea5ebb4dc1ecd7a1f700607645df0033ff81bb7e3e6d6cdfc96d0ca98",
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
