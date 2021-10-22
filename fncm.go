package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	// DefaultBufferSize 1MB
	DefaultBufferSize = 1 << 20
)

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
		if len(v) > 1 {
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

	ncm    *os.File
	reader *bufio.Reader
	writer *bufio.Writer

	err          error
	rc4SBoxKey   []byte
	rc4StreamKey []byte
	meta         *Meta
	image        []byte
	imageLeft    int
	fileName     string
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
	fn.saveMusic()
	fn.embedMeta()

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

	extname := filepath.Ext(fn.input)
	basename := filepath.Base(fn.input)
	filename := strings.TrimSuffix(basename, extname)
	fn.fileName = fmt.Sprintf("%s.%s", filename, fn.meta.Format)
	fn.fileName = filepath.Join(fn.output, fn.fileName)
	f, err := os.Create(fn.fileName)
	if err != nil {
		fn.err = err
		return
	}
	defer func() {
		_ = f.Sync()
		_ = f.Close()
	}()
	fn.writer.Reset(f)
	defer func() {
		_ = fn.writer.Flush()
	}()

	for i, b := 0, byte(0); ; i++ {
		b, err = fn.reader.ReadByte()
		if err == io.EOF {
			return
		}
		if err != nil {
			fn.err = err
			return
		}
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
	mp3File, err := id3v2.Open(fn.fileName, id3v2.Options{Parse: false})
	if err != nil {
		return err
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
	return mp3File.Save()
}

// embedMetaFlac 不要在主流程中调用
func (fn *FNcm) embedMetaFlac() error {
	flacFile, err := flac.ParseFile(fn.fileName)
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
				return err
			}
			vcIndex = i
		}
		if meta.Type == flac.Picture {
			pic, err = flacpicture.ParseFromMetaDataBlock(*meta)
			if err != nil {
				return err
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
	mdb := vc.Marshal()
	if vcIndex >= 0 {
		flacFile.Meta[vcIndex] = &mdb
	} else {
		flacFile.Meta = append(flacFile.Meta, &mdb)
	}

	if pic == nil {
		pic, err = flacpicture.NewFromImageData(flacpicture.PictureTypeFrontCover, "Front cover",
			fn.image, fn.imageFormat())
	}
	mdb = pic.Marshal()
	if picIndex >= 0 {
		flacFile.Meta[picIndex] = &mdb
	} else {
		flacFile.Meta = append(flacFile.Meta, &mdb)
	}
	return flacFile.Save(fn.fileName)
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
