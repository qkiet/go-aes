package aesbasic

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func HexStringToBytes(s string) ([]byte, error) {
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

func ConvertHexStringsToBytesAndCheck(t *testing.T, s string) []byte {
	b, err := HexStringToBytes(s)
	assert.NoError(t, err)
	return b
}
