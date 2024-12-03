package aesbasic

import (
	"fmt"

	"github.com/qkiet/aes-from-specs/common"
)

func AES128Encrypt(pt []byte, k common.Aes128Key) ([]byte, error) {
	var state common.AesState
	var err error
	var expandedKeyWords []common.AesWord
	var keyState common.AesState
	expandedKey := KeyExpansion(common.Aes128KeyToBytes(k))
	if expandedKeyWords, err = common.BytesToWords(expandedKey); err != nil {
		return nil, fmt.Errorf("not able to convert expanded key bytes to expanded key words: %v", err)
	}
	if state, err = common.BytesToAesState(pt); err != nil {
		return nil, fmt.Errorf("not able to convert plain text to AES state: %v", err)
	}
	// No need to check error, 0:4 guarantee to be 4 words and convert to AesState success
	keyState, _ = common.WordsToAesState(expandedKeyWords[0:4])
	state = AddRoundKey(state, keyState)
	for r := 1; r < common.Aes128_NumRound; r++ {
		state = SubBytes(state)
		state = ShiftRows(state)
		state = MixColumns(state)
		keyState, _ = common.WordsToAesState(expandedKeyWords[4*r : 4*(r+1)])
		state = AddRoundKey(state, keyState)
	}
	state = SubBytes(state)
	state = ShiftRows(state)
	keyState, _ = common.WordsToAesState(expandedKeyWords[4*common.Aes128_NumRound : 4*(common.Aes128_NumRound+1)])
	state = AddRoundKey(state, keyState)
	return common.AesStateToBytes(state), nil
}

func AES128Decrypt(ct []byte, k common.Aes128Key) ([]byte, error) {
	var state common.AesState
	var err error
	var expandedKeyWords []common.AesWord
	var keyState common.AesState
	expandedKey := KeyExpansionEic(common.Aes128KeyToBytes(k))
	if expandedKeyWords, err = common.BytesToWords(expandedKey); err != nil {
		return nil, fmt.Errorf("not able to convert expanded key bytes to expanded key words: %v", err)
	}
	if state, err = common.BytesToAesState(ct); err != nil {
		return nil, fmt.Errorf("not able to convert cipher text to AES state: %v", err)
	}
	// No need to check error, 0:4 guarantee to be 4 words and convert to AesState success
	keyState, _ = common.WordsToAesState(expandedKeyWords[4*common.Aes128_NumRound : 4*(common.Aes128_NumRound+1)])
	state = AddRoundKey(state, keyState)
	for r := common.Aes128_NumRound - 1; r > 0; r-- {
		state = InvSubBytes(state)
		state = InvShiftRows(state)
		state = InvMixColumns(state)
		keyState, _ = common.WordsToAesState(expandedKeyWords[4*r : 4*(r+1)])
		state = AddRoundKey(state, keyState)
	}
	state = InvSubBytes(state)
	state = InvShiftRows(state)
	keyState, _ = common.WordsToAesState(expandedKeyWords[0:4])
	state = AddRoundKey(state, keyState)
	return common.AesStateToBytes(state), nil
}
