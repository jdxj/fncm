package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	// DefaultBufferSize 1MB
	DefaultBufferSize = 1 << 20
)

func NewFNcm(input, output string) *FNcm {
	fn := &FNcm{
		input:  input,
		output: output,
		reader: bufio.NewReaderSize(nil, DefaultBufferSize),
		writer: bufio.NewWriterSize(nil, DefaultBufferSize),
	}
	return fn
}

type FNcm struct {
	// input specifies the file to be decoded
	input string
	// output specifies the storage path
	output string

	ncm    *os.File
	reader *bufio.Reader
	writer *bufio.Writer

	err          error
	rc4SBoxKey   []byte
	rc4StreamKey []byte
}

func (fn *FNcm) Decrypt() error {
	fn.openNCM()
	fn.verifyMagicHeader()
	fn.skipUnknownBytes(2)
	fn.decryptRC4SBoxKey()

	fn.close()
	return fn.err
}

func (fn *FNcm) skipUnknownBytes(size int) {
	if fn.err != nil {
		return
	}

	_, err := fn.reader.Discard(size)
	if err != nil {
		fn.err = fmt.Errorf("%w: %s", ErrSkipBytesFailed, err)
	}
}

func (fn *FNcm) close() {
	_ = fn.ncm.Close()
}

func (fn *FNcm) openNCM() {
	// todo: file.close()
	fn.ncm, fn.err = os.OpenFile(fn.input, os.O_RDONLY, 0400)
	if fn.err != nil {
		return
	}
	fn.reader.Reset(fn.ncm)
	return
}

func (fn *FNcm) verifyMagicHeader() {
	if fn.err != nil {
		return
	}

	buf := make([]byte, MagicHeaderSize)
	_, err := io.ReadFull(fn.reader, buf)
	if err != nil {
		fn.err = fmt.Errorf("%w: %s", ErrVerifyMagicHeaderFailed, err)
		return
	}
	if !bytes.Equal(MagicHeader, buf) {
		fn.err = fmt.Errorf("%w: not ncm file", ErrVerifyMagicHeaderFailed)
		return
	}
}

func (fn *FNcm) readBytesByLeading() ([]byte, error) {
	buf := make([]byte, LeadingSize)
	_, err := io.ReadFull(fn.reader, buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrReadDataFailed, err)
	}
	dataSize := binary.LittleEndian.Uint32(buf)
	buf = make([]byte, dataSize)
	_, err = io.ReadFull(fn.reader, buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrReadDataFailed, err)
	}
	return buf, nil
}

func (fn *FNcm) decryptRC4SBoxKey() {
	if fn.err != nil {
		return
	}

	data, err := fn.readBytesByLeading()
	if err != nil {
		fn.err = err
		return
	}
	for i := range data {
		data[i] ^= 0x64
	}
	data, err = AESDecryptECB(AESKey, data)
	if err != nil {
		fn.err = err
		return
	}
	// 跳过 `neteasecloudmusic` 17个字符
	fn.rc4SBoxKey = data[17:]
}

func (fn *FNcm) decryptRC4StreamKey() {
	if fn.err != nil {
		return
	}

	// 1. 初始化
	sBox := make([]byte, RC4SBoxSize)
	for i := 0; i < RC4SBoxSize; i++ {
		sBox[i] = byte(i)
	}
	// 2. 打乱
	sBoxKey := fn.rc4SBoxKey
	sBoxKeySize := len(sBoxKey)
	for i, j := 0, 0; i < RC4SBoxSize; i++ {
		j = (j + int(sBox[i]) + int(sBoxKey[i%sBoxKeySize])) % RC4SBoxSize
		sBox[i], sBox[j] = sBox[j], sBox[i]
	}
	// 3. 生成流密钥
	streamKey := make([]byte, RC4SBoxSize)
	for i := 0; i < RC4SBoxSize; i++ {
		j := (int(sBox[i]) + int(sBox[(i+int(sBox[i]))&0xFF])) & 0xFF
		streamKey[i] = sBox[j]
	}
	fn.rc4StreamKey = streamKey
}
