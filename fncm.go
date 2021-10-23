package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bogem/id3v2"
	"github.com/go-flac/flacpicture"
	"github.com/go-flac/flacvorbis"
	"github.com/go-flac/go-flac"
)

const (
	LeadingSize       = 4
	RC4SBoxSize       = 256
	DefaultBufferSize = 8 * (1 << 20) // x * 1MB
)

var (
	MagicHeader = []byte{0x43, 0x54, 0x45, 0x4e, 0x46, 0x44, 0x41, 0x4d}
	AESKey      = []byte{0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57}
	MetaKey     = []byte{0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28}
	PngHeader   = []byte{0x89, 0x50, 0x4E, 0x47}

	PngHeaderSize   = len(PngHeader)
	MagicHeaderSize = len(MagicHeader)
)

var (
	ErrVerifyMagicHeaderFailed = errors.New("verify magic header failed")
	ErrSkipBytesFailed         = errors.New("skip bytes failed")
	ErrReadDataFailed          = errors.New("reader data failed")
	ErrAESDecryptECBFailed     = errors.New("aes decrypt ecb failed")
	ErrMetaDecryptFailed       = errors.New("meta decrypt failed")
	ErrEmbedMetaMp3Failed      = errors.New("embed meta mp3 failed")
	ErrEmbedMetaFlacFailed     = errors.New("embed meta flac failed")
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

type Meta struct {
	Format        string          `json:"format"`
	MusicID       int             `json:"musicId"`
	MusicName     string          `json:"musicName"`
	Artist        [][]interface{} `json:"artist"`
	Album         string          `json:"album"`
	AlbumID       int             `json:"albumId"`
	AlbumPicDocID uint64          `json:"albumPicDocId"`
	AlbumPic      string          `json:"albumPic"`
	MVID          int             `json:"mvId"`
	Flag          int             `json:"flag"`
	Bitrate       int             `json:"bitrate"`
	Duration      int             `json:"duration"`
	Alias         json.RawMessage `json:"alias"`      // 没见到数据, 不知其类型
	TransNames    json.RawMessage `json:"transNames"` // 没见到数据, 不知其类型
}

func (m *Meta) MustFormat() string {
	if m == nil {
		return "mp3"
	}
	return m.Format
}

func (m *Meta) MustArtist() string {
	if m == nil {
		return ""
	}

	var artist string
	names := make([]string, 0, len(m.Artist))
	for _, v := range m.Artist {
		if len(v) > 0 {
			names = append(names, fmt.Sprintf("%v", v[0]))
		}
	}
	artist = strings.Join(names, "/")
	return artist
}

func (m *Meta) MustMusicName() string {
	if m == nil {
		return ""
	}
	return m.MusicName
}

func (m *Meta) MustAlbum() string {
	if m == nil {
		return ""
	}
	return m.Album
}

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

	reader *bufio.Reader
	writer *bufio.Writer
	ncm    *os.File
	music  *os.File

	rc4SBoxKey   []byte
	rc4StreamKey []byte
	image        []byte
	err          error
	imageLeft    int
	meta         *Meta
	outPath      string
}

// Decrypt 主流程
func (fn *FNcm) Decrypt() error {
	fn.openNCM()
	fn.verifyMagicHeader()
	fn.skipUnknownBytes(2)
	fn.decryptRC4SBoxKey()
	fn.decryptRC4StreamKey()
	fn.decryptMeta()
	fn.skipUnknownBytes(5)
	fn.decryptImage()
	fn.skipUnknownBytes(fn.imageLeft)
	fn.createMusic()
	fn.saveMusic()
	fn.closeFile()
	fn.embedMeta()
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

func (fn *FNcm) openNCM() {
	if fn.err != nil {
		return
	}

	fn.ncm, fn.err = os.OpenFile(fn.input, os.O_RDONLY, 0400)
	if fn.err != nil {
		return
	}
	fn.reader.Reset(fn.ncm)
	return
}

func (fn *FNcm) createMusic() {
	if fn.err != nil {
		return
	}

	ext := filepath.Ext(fn.input)
	base := filepath.Base(fn.input)
	filename := strings.TrimSuffix(base, ext)
	base = fmt.Sprintf("%s.%s", filename, fn.meta.Format)
	fn.outPath = filepath.Join(fn.output, base)
	fn.music, fn.err = os.Create(fn.outPath)
	if fn.err != nil {
		return
	}
	fn.writer.Reset(fn.music)
}

func (fn *FNcm) closeFile() {
	if fn.ncm != nil {
		_ = fn.ncm.Close()
	}
	_ = fn.writer.Flush()
	if fn.music != nil {
		_ = fn.music.Sync()
		_ = fn.music.Close()
	}
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

// readBytesByLeading 不要再主流程中使用
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

// readUint32 不要在主流程中使用
func (fn *FNcm) readUint32() (uint32, error) {
	buf := make([]byte, LeadingSize)
	_, err := io.ReadFull(fn.reader, buf)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrReadDataFailed, err)
	}
	return binary.LittleEndian.Uint32(buf), nil
}

// readBytes 不要在主流程中使用
func (fn *FNcm) readBytes(size uint32) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(fn.reader, buf)
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
		j = (j + int(sBox[i]) + int(sBoxKey[i%sBoxKeySize])) & 0xFF
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

func (fn *FNcm) decryptMeta() {
	if fn.err != nil {
		return
	}

	data, err := fn.readBytesByLeading()
	if err != nil {
		fn.err = err
		return
	}
	if len(data) < 22 {
		fn.err = fmt.Errorf("%w: unexpected meta format", ErrMetaDecryptFailed)
		return
	}

	for i := range data {
		data[i] ^= 0x63
	}
	// 跳过 `163 key(Don't modify):` 22个字符
	data, err = base64.StdEncoding.DecodeString(string(data[22:]))
	if err != nil {
		fn.err = err
		return
	}
	data, err = AESDecryptECB(MetaKey, data)
	if err != nil {
		fn.err = err
		return
	}
	// 跳过 `music:` 6个字符
	err = json.Unmarshal(data[6:], &fn.meta)
	if err != nil {
		fn.err = err
		return
	}
}

func (fn *FNcm) decryptImage() {
	if fn.err != nil {
		return
	}

	spaceSize, err := fn.readUint32()
	if err != nil {
		fn.err = err
		return
	}
	imageSize, err := fn.readUint32()
	if err != nil {
		fn.err = err
		return
	}
	if imageSize > 0 {
		data, err := fn.readBytes(imageSize)
		if err != nil {
			fn.err = err
			return
		}
		fn.image = data
	}
	fn.imageLeft = int(spaceSize - imageSize)
}

func (fn *FNcm) saveMusic() {
	if fn.err != nil {
		return
	}

	for i := 0; ; i++ {
		b, err := fn.reader.ReadByte()
		if err == io.EOF {
			return
		}
		if err != nil {
			fn.err = err
			return
		}
		// 用时间换空间
		err = fn.writer.WriteByte(b ^ fn.rc4StreamKey[(i+1)%RC4SBoxSize])
		if err != nil {
			fn.err = err
			return
		}
	}
}

// imageFormat 不要在主流程调用
func (fn *FNcm) imageFormat() string {
	imageFormat := "image/jpeg"
	if len(fn.image) < PngHeaderSize {
		return imageFormat
	}
	if bytes.Equal(fn.image[:PngHeaderSize], PngHeader) {
		imageFormat = "image/png"
	}
	return imageFormat
}

// embedMetaMp3 不要在主流程调用
func (fn *FNcm) embedMetaMp3() error {
	mp3File, err := id3v2.Open(fn.outPath, id3v2.Options{Parse: false})
	if err != nil {
		return fmt.Errorf("%w: %s", ErrEmbedMetaMp3Failed, err)
	}
	defer func() {
		_ = mp3File.Close()
	}()

	artistName := fn.meta.MustArtist()
	mp3File.SetDefaultEncoding(id3v2.EncodingUTF8)
	mp3File.SetArtist(artistName)
	mp3File.SetTitle(fmt.Sprintf("%v", fn.meta.MustMusicName()))
	mp3File.SetAlbum(fmt.Sprintf("%v", fn.meta.MustAlbum()))

	imageFormat := fn.imageFormat()
	if len(fn.image) > 0 {
		pic := id3v2.PictureFrame{
			Encoding:    id3v2.EncodingISO,
			MimeType:    imageFormat,
			PictureType: id3v2.PTFrontCover,
			Description: "Front cover",
			Picture:     fn.image,
		}
		mp3File.AddAttachedPicture(pic)
	}
	err = mp3File.Save()
	if err != nil {
		err = fmt.Errorf("%w: %s", ErrEmbedMetaMp3Failed, err)
	}
	return err
}

// embedMetaFlac 不要在主流程中调用
func (fn *FNcm) embedMetaFlac() error {
	flacFile, err := flac.ParseFile(fn.outPath)
	if err != nil {
		return err
	}

	var (
		vcIndex  = -1
		picIndex = -1

		vc  *flacvorbis.MetaDataBlockVorbisComment
		pic *flacpicture.MetadataBlockPicture
	)
	for i, meta := range flacFile.Meta {
		if meta.Type == flac.VorbisComment {
			vc, err = flacvorbis.ParseFromMetaDataBlock(*meta)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrEmbedMetaFlacFailed, err)
			}
			vcIndex = i
		}
		if meta.Type == flac.Picture {
			pic, err = flacpicture.ParseFromMetaDataBlock(*meta)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrEmbedMetaFlacFailed, err)
			}
			picIndex = i
		}
	}
	if vc == nil {
		vc = flacvorbis.New()
	}
	_ = vc.Add(flacvorbis.FIELD_TITLE, fn.meta.MustMusicName())
	_ = vc.Add(flacvorbis.FIELD_ALBUM, fn.meta.MustAlbum())
	_ = vc.Add(flacvorbis.FIELD_ARTIST, fn.meta.MustArtist())
	mdbVC := vc.Marshal()
	if vcIndex >= 0 {
		flacFile.Meta[vcIndex] = &mdbVC
	} else {
		flacFile.Meta = append(flacFile.Meta, &mdbVC)
	}

	if pic == nil {
		pic, err = flacpicture.NewFromImageData(flacpicture.PictureTypeFrontCover, "Front cover",
			fn.image, fn.imageFormat())
		if err != nil {
			return fmt.Errorf("%w: %s", ErrEmbedMetaFlacFailed, err)
		}
	}
	mdbPic := pic.Marshal()
	if picIndex >= 0 {
		flacFile.Meta[picIndex] = &mdbPic
	} else {
		flacFile.Meta = append(flacFile.Meta, &mdbPic)
	}
	err = flacFile.Save(fn.outPath)
	if err != nil {
		err = fmt.Errorf("%w: %s", ErrEmbedMetaFlacFailed, err)
	}
	return err
}

func (fn *FNcm) embedMeta() {
	if fn.err != nil {
		return
	}

	var err error
	if fn.meta.MustFormat() == "mp3" {
		err = fn.embedMetaMp3()
	} else if fn.meta.MustFormat() == "flac" {
		err = fn.embedMetaFlac()
	}
	if err != nil {
		fn.err = err
		return
	}
}
