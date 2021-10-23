package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-flac/flacpicture"
	"github.com/go-flac/flacvorbis"
	"github.com/go-flac/go-flac"
)

func TestMod(t *testing.T) {
	fmt.Printf("%d\n", 6%3)
	fmt.Printf("%d\n", 6&(2))
	// 110
	//  11
	// ---
	// 010
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

func TestFlacMeta(t *testing.T) {
	flacFile, err := flac.ParseFile("./music.flac")
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	for _, v := range flacFile.Meta {
		fmt.Printf("type: %d\n", v.Type)
		if v.Type == flac.VorbisComment {
			b, err := flacvorbis.ParseFromMetaDataBlock(*v)
			if err != nil {
				t.Errorf("%s\n", err)
			}
			fmt.Printf("%v\n", b.Comments)
		}
		if v.Type == flac.Picture {
			b, err := flacpicture.ParseFromMetaDataBlock(*v)
			if err != nil {
				t.Errorf("%s\n", err)
			}
			fmt.Printf("pic describe: %s\n", b.Description)
			fmt.Printf("pic size: %d\n", len(b.ImageData))
		}
	}
}

func TestFNcm_Decrypt(t *testing.T) {
	t1 := time.Now()
	fn := NewFNcm("./music.ncm", "./")
	err := fn.Decrypt()
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	fmt.Printf("rc4SBoxKey: %s\n", base64.StdEncoding.EncodeToString(fn.rc4SBoxKey))
	fmt.Printf("rc4StreamKey: %s\n", base64.StdEncoding.EncodeToString(fn.rc4StreamKey))
	fmt.Printf("meta: %+v\n", fn.meta)
	fmt.Printf("meta: artist: %s\n", fn.meta.MustArtist())
	//fmt.Printf("image: %s\n", base64.StdEncoding.EncodeToString(fn.image))
	fmt.Printf("mime header: %x\n", fn.image[:4])

	fmt.Printf("imageLeft: %d\n", fn.imageLeft)
	f, err := os.Create("./abc.jpg")
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	defer f.Close()
	_, err = f.Write(fn.image)
	if err != nil {
		t.Fatalf("%s\n", err)
	}

	fmt.Printf("since: %d\n", time.Since(t1).Milliseconds())
}

func TestFile(t *testing.T) {
	info, err := os.Stat("music.flac")
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	fmt.Printf("name: %s\n", info.Name())
	fmt.Printf("ext: %s\n", filepath.Ext(info.Name()))
	abs, err := filepath.Abs(info.Name())
	if err != nil {
		t.Fatalf("%s\n", err)
	}
	fmt.Printf("abs: %s\n", abs)
}
