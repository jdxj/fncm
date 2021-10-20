package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

var (
	// 687A4852416D736F356B496E62617857
	coreBytes  = []byte{0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57}
	// 2331346C6A6B5F215C5D2630553C2728
	metaBytes  = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
	// 4354454e4644414d
	magicBytes = []byte{0x43, 0x54, 0x45, 0x4e, 0x46, 0x44, 0x41, 0x4d}
)

func PrintAscii(bytes []byte) {
	fmt.Printf("%s\n", bytes)
}

func ConvertToLittle(bytes []byte) uint32 {
	return binary.LittleEndian.Uint32(bytes)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("需要文件路径")
	}

	filePath := os.Args[1]
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0400)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	log.Println("open ok")

}