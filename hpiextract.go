package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"os"
)

type Header struct {
	HPIMarker     []byte // HAPI
	SaveMarker    []byte // BANK if a save
	DirectorySize uint32 // The size of the directory
	HeaderKey     uint32 // Decrypt key
	Start         uint32 // File offset of directory
}
type Entry struct {
	NameOffset    uint32 // Points to the filename
	DirDataOffset uint32 // Points to the directory data
	Flag          byte   // File flag
}
type FileData struct {
	DataOffset uint32 // Starting offset of the file
	FileSize   uint32 // Size of the decompressed file
	Flag       byte   // File flag
	// If Flag is 1, file is compressed iwth LZ77
	// If Flag is 2, file is compressed with ZLib
	// If Flag is 0, the file is not compressed
}
type Chunk struct {
	Size             uint32 // Size of the chunk
	Marker           []byte // SQSH
	Unknown1         byte
	CompMethod       byte   // 1=LZ77, 2=ZLib
	Encrypt          byte   // Is the block encrypted?
	CompressedSize   uint32 // Length of the compressed data
	DecompressedSize uint32 // Length of the decompressed data
	Checksum         uint32 // Actually a sum of all the bytes of the data
	Data             []byte // 'CompressedSize' bytes of data
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, "usage: hpiextract file.hpi out_dir\n")
		os.Exit(1)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	header, err := ScanHeader(file)
	if err != nil {
		log.Fatal(err)
	}
	TraverseTree(file, os.Args[2], int64(header.Start))
}

// TraverseTree recursively prints directories and filenames
func TraverseTree(obj io.ReadSeeker, parent string, offset int64) {
	tmp := make([]byte, 4)
	_, err := obj.Seek(offset, 0)
	if err != nil {
		log.Fatal(err)
	}
	lr := io.LimitReader(obj, 4)
	if _, err = io.ReadFull(lr, tmp); err != nil {
		log.Fatal(err)
	}
	numEntries := binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		log.Fatal(err)
	}
	entryOffset := binary.LittleEndian.Uint32(tmp)
	_, err = obj.Seek(int64(entryOffset), 0)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < int(numEntries); i++ {
		_, err = obj.Seek(int64(entryOffset)+(int64(i)*9), 0)
		if err != nil {
			log.Fatal(err)
		}
		entry, err := ScanEntry(obj)
		if err != nil {
			log.Fatal(err)
		}
		_, err = obj.Seek(int64(entry.NameOffset), 0)
		if err != nil {
			log.Fatal(err)
		}
		nameReader := bufio.NewReader(obj)
		fileName, err := nameReader.ReadBytes('\x00')
		if err != nil {
			log.Fatal(err)
		}
		name := fmt.Sprintf("%s/%s", parent, string(fileName[:len(fileName)-1]))
		if entry.Flag == 1 {
			TraverseTree(obj, name, int64(entry.DirDataOffset))
		} else {
			// Create the directory if it doesn't exist.
			if _, err := os.Stat(parent); os.IsNotExist(err) {
				err = os.MkdirAll(parent, 0755)
				if err != nil {
					log.Fatal(err)
				}
			}
			_, err := obj.Seek(int64(entry.DirDataOffset), 0)
			if err != nil {
				log.Fatal(err)
			}
			fileData, err := ScanFileData(obj)
			if err != nil {
				log.Fatal(err)
			}
			chunks := int(math.Ceil(float64(fileData.FileSize) / 65536))
			if int(fileData.FileSize)%65536 == 0 {
				chunks++
			}
			_, err = obj.Seek(int64(fileData.DataOffset), 0)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(name)
			err = ProcessFile(obj, name, chunks)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

// ProcessFile extracts the chunk at the cursor and writes it as
// a file
func ProcessFile(obj io.ReadSeeker, name string, chunks int) error {
	// Create the file to write the contents to
	outFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer outFile.Close()
	var buf, input io.Reader
	for i := 0; i < chunks; i++ {
		chunk, err := ScanChunk(obj)
		if err != nil {
			return err
		}
		if chunk.Encrypt == 1 {
			buf = bytes.NewReader(chunk.Decrypt())
		} else {
			buf = bytes.NewReader(chunk.Data)
		}
		switch method := chunk.CompMethod; method {
		case 0:
			input = buf
		case 1:
			log.Fatal("Chunk uses LZ77 compression. Reader not implemented")
		case 2:
			input, err = zlib.NewReader(buf)
			if err != nil {
				return err
			}
		}

		io.Copy(outFile, input)
	}
	return nil
}

func (chunk *Chunk) Decrypt() []byte {
	result := make([]byte, int(chunk.CompressedSize))
	for i := 0; i < int(chunk.CompressedSize); i++ {
		result[i] = (chunk.Data[i] - byte(i)) ^ byte(i)
	}
	return result
}

// ScanChunk scans the bytes from the current offset into
// a *Chunk
func ScanChunk(obj io.ReadSeeker) (*Chunk, error) {
	chunk := &Chunk{}
	tmp := make([]byte, 4)
	lr := io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	if bytes.Equal(tmp, []byte{0x53, 0x51, 0x53, 0x48}) {
		chunk.Marker = tmp
	}
	//chunk.Size = binary.LittleEndian.Uint32(tmp)
	for chunk.Marker == nil {
		lr = io.LimitReader(obj, 4)
		if _, err := io.ReadFull(lr, tmp); err != nil {
			return nil, err
		}
		if bytes.Equal(tmp, []byte{0x53, 0x51, 0x53, 0x48}) {
			chunk.Marker = tmp
		}
	}
	tmp = make([]byte, 1)
	lr = io.LimitReader(obj, 1)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.Unknown1 = tmp[0]

	lr = io.LimitReader(obj, 1)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.CompMethod = tmp[0]

	lr = io.LimitReader(obj, 1)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.Encrypt = tmp[0]

	tmp = make([]byte, 4)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.CompressedSize = binary.LittleEndian.Uint32(tmp)

	tmp = make([]byte, 4)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.DecompressedSize = binary.LittleEndian.Uint32(tmp)

	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.Checksum = binary.LittleEndian.Uint32(tmp)

	tmp = make([]byte, int(chunk.CompressedSize))
	lr = io.LimitReader(obj, int64(chunk.CompressedSize))
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	chunk.Data = tmp

	return chunk, nil
}

// ScanEntry scans the bytes from the current offset into
// an *Entry
func ScanEntry(obj io.ReadSeeker) (*Entry, error) {
	entry := &Entry{}
	tmp := make([]byte, 4)
	tmp1 := make([]byte, 1)
	lr := io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	entry.NameOffset = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	entry.DirDataOffset = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 1)
	if _, err := io.ReadFull(lr, tmp1); err != nil {
		return nil, err
	}
	entry.Flag = tmp1[0]
	return entry, nil
}

// ScanFileData seeks to the offset and scans the bytes from
// there into a *FileData
func ScanFileData(obj io.ReadSeeker) (*FileData, error) {
	fileData := &FileData{}
	tmp := make([]byte, 4)
	tmp1 := make([]byte, 1)
	lr := io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	fileData.DataOffset = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	fileData.FileSize = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 1)
	if _, err := io.ReadFull(lr, tmp1); err != nil {
		return nil, err
	}
	fileData.Flag = tmp1[0]
	return fileData, nil
}

// ScanHeader moves the cursor to the beginning of the file
// and then returns an Header struct
func ScanHeader(obj io.ReadSeeker) (*Header, error) {
	header := &Header{
		HPIMarker:  make([]byte, 4),
		SaveMarker: make([]byte, 4),
	}
	tmp := make([]byte, 4)
	_, err := obj.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	lr := io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, header.HPIMarker); err != nil {
		return nil, err
	}
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, header.SaveMarker); err != nil {
		return nil, err
	}
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	header.DirectorySize = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	header.HeaderKey = binary.LittleEndian.Uint32(tmp)
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp); err != nil {
		return nil, err
	}
	header.Start = binary.LittleEndian.Uint32(tmp)
	return header, err
}
