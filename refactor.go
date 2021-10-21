package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

	MetaHeader     = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
	MetaHeaderSize = len(MetaHeader)
)

var (
	ErrVerifyMagicHeaderFailed = errors.New("verify magic header failed")
	ErrSkipBytesFailed         = errors.New("skip bytes failed")
	ErrReadDataFailed          = errors.New("reader data failed")
	ErrAESDecryptECBFailed     = errors.New("aes decrypt ecb failed")
	ErrRC4DecryptFailed        = errors.New("rc4 decrypt failed")
)

func VerifyMagicHeader(reader io.Reader) error {
	buf := make([]byte, MagicHeaderSize)
	_, err := reader.Read(buf)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrVerifyMagicHeaderFailed, err)
	}

	if !bytes.Equal(MagicHeader, buf) {
		return fmt.Errorf("%w: not ncm file", ErrVerifyMagicHeaderFailed)
	}
	return nil
}

func SkipUnknownBytes(reader io.Seeker, size int64) error {
	_, err := reader.Seek(size, 1)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrSkipBytesFailed, err)
	}
	return nil
}

func ReadBytesByLeading(reader io.Reader) ([]byte, error) {
	leadingBytes := make([]byte, LeadingSize)
	n, err := reader.Read(leadingBytes)
	if n < LeadingSize || err != nil {
		return nil, fmt.Errorf("%w: n: %d, err: %s", ErrReadDataFailed, n, err)
	}

	dataSize := binary.LittleEndian.Uint32(leadingBytes)
	dataBytes := make([]byte, dataSize)
	n, err = reader.Read(dataBytes)
	if n < len(dataBytes) || err != nil {
		return nil, fmt.Errorf("%w: n: %d, err: %s", ErrReadDataFailed, n, err)
	}
	return dataBytes, nil
}

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

// RC4SBox 根据 key 生成 S 盒 https://zh.wikipedia.org/wiki/RC4
func RC4SBox(key []byte) []byte {
	// 1. 初始化
	sBox := make([]byte, RC4SBoxSize)
	for i := 0; i < RC4SBoxSize; i++ {
		sBox[i] = byte(i)
	}

	// 2. 打乱
	keySize := len(key)
	for i, j := 0, 0; i < RC4SBoxSize; i++ {
		j = (j + int(sBox[i]) + int(key[i%keySize])) % RC4SBoxSize
		sBox[i], sBox[j] = sBox[j], sBox[i]
	}
	return sBox
}

func RC4StreamKey(sBox []byte) []byte {
	streamKey := make([]byte, RC4SBoxSize)
	for i := 0; i < RC4SBoxSize; i++ {
		j := (int(sBox[i]) + int(sBox[(i+int(sBox[i]))&0xFF])) & 0xFF
		streamKey[i] = sBox[j]
	}
	return streamKey
}

func RC4Encrypt(key, ciphertext []byte) []byte {
	sBox := RC4SBox(key)
	sKey := RC4StreamKey(sBox)

	res := make([]byte, 0, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		res = append(res, ciphertext[i]^sKey[(i+1)%RC4SBoxSize])
	}
	return res
}

func RC4EncryptTest(key []byte, reader io.Reader, writer io.Writer) error {
	bufReader := bufio.NewReader(reader)
	bufWriter := bufio.NewWriter(writer)
	defer func() {
		_ = bufWriter.Flush()
	}()

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrRC4DecryptFailed, err)
	}

	src := make([]byte, BufferSize)
	des := make([]byte, BufferSize)
	for n, err := bufReader.Read(src); err == nil; n, err = bufReader.Read(src) {
		cipher.XORKeyStream(des[:n], src[:n])
		_, err := bufWriter.Write(des[:n])
		if err != nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", ErrRC4DecryptFailed, err)
	}
	return err
}
