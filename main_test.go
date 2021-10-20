package main

import (
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
