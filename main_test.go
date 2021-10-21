package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestPrintAscii(t *testing.T) {
	PrintAscii(coreBytes)
	PrintAscii(metaBytes)
	PrintAscii(magicBytes)
}

func TestConvertToLittle(t *testing.T) {
	v := ConvertToLittle([]byte{0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	fmt.Printf("%d\n", v)
}

func TestGenerateKey(t *testing.T) {
	res := generateKey(coreBytes)
	for _, v := range coreBytes {
		fmt.Printf("%x, ", v)
	}
	fmt.Println()
	for _, v := range res {
		fmt.Printf("%x, ", v)
	}
}

func TestMod(t *testing.T) {
	fmt.Printf("%d\n", 7%3)
	fmt.Printf("%d\n", 7&3)
}

func rawRC4(key, data []byte) string {
	keySize := len(key)

	// s 盒初始化
	s := make([]byte, 256)
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0

	// RC4-KSA算法生成S盒
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%keySize])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}

	// RC4 生成流密钥
	stream := make([]byte, 256)
	for i := 0; i < 256; i++ {
		j := (int(s[i]) + int(s[(i+int(s[i]))&0xFF])) & 0xFF
		stream[i] = s[j]
	}

	// 流密钥到 data 的映射
	// 用求余, 没必要生成
	newStream := make([]byte, 0)
	for i := 0; i < len(data); i++ {
		v := stream[(i+1)%256]
		newStream = append(newStream, v)
	}

	newData := strxor(string(data), string(newStream))
	return base64.StdEncoding.EncodeToString([]byte(newData))
}

func TestRC4(t *testing.T) {
	data := []byte{'a', 'b', 'c'}
	res := rawRC4(AESKey, data)
	fmt.Printf("res1: %s\n", res)

	r := bytes.NewReader(data)

	bw := &base64Writer{}
	err := RC4Encrypt(AESKey, r, bw)
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	fmt.Printf("res2: %s\n", bw.Result())
}

type base64Writer struct {
	buf []byte
}

func (bw *base64Writer) Write(p []byte) (int, error) {
	bw.buf = append(bw.buf, p...)
	return len(p), nil
}

func (bw *base64Writer) Result() string {
	return base64.StdEncoding.EncodeToString(bw.buf)
}
