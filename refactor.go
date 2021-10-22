package main

import (
	"crypto/aes"
	"errors"
	"fmt"
)

const (
	LeadingSize = 4
	RC4SBoxSize = 256

	BufferSize = 1 << 20
)

var (
	MagicHeader     = []byte{0x43, 0x54, 0x45, 0x4e, 0x46, 0x44, 0x41, 0x4d}
	MagicHeaderSize = len(MagicHeader)

	AESKey     = []byte{0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57}
	AESKeySize = len(AESKey)

	MetaKey        = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
	MetaHeaderSize = len(MetaKey)

	PngHeader     = []byte{0x89, 0x50, 0x4E, 0x47}
	PngHeaderSize = len(PngHeader)
)

var (
	ErrVerifyMagicHeaderFailed = errors.New("verify magic header failed")
	ErrSkipBytesFailed         = errors.New("skip bytes failed")
	ErrReadDataFailed          = errors.New("reader data failed")
	ErrAESDecryptECBFailed     = errors.New("aes decrypt ecb failed")
	ErrRC4DecryptFailed        = errors.New("rc4 decrypt failed")
	ErrMetaDecryptFailed       = errors.New("meta decrypt failed")
)

func AESDecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAESDecryptECBFailed, err)
	}
	blockSize := block.BlockSize()

	dataSize := len(ciphertext)
	if dataSize < blockSize {
		return nil, fmt.Errorf("%w: invalid ciphertext", ErrAESDecryptECBFailed)
	}
	plaintext := make([]byte, dataSize)

	for start := 0; start < dataSize; start += blockSize {
		end := start + blockSize
		block.Decrypt(plaintext[start:end], ciphertext[start:end])
	}

	trim := dataSize - int(plaintext[dataSize-1])
	return plaintext[:trim], nil
}
