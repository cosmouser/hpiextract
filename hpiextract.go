package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
)

type HPIHeader struct {
	HPIMarker     []byte // HAPI
	SaveMarker    []byte // BANK if a save
	DirectorySize uint32 // The size of the directory
	HeaderKey     uint32 // Decrypt key
	Start         uint32 // File offset of directory
}
type HPIEntry struct {
	NameOffset    uint32 // Points to the filename
	DirDataOffset uint32 // Points to the directory data
	Flag          byte   // File flag
}
type HPIFileData struct {
	DataOffset uint32 // Starting offset of the file
	FileSize   uint32 // Size of the decompressed file
	Flag       byte   // File flag
	// If Flag is 1, file is compressed iwth LZ77
	// If Flag is 2, file is compressed with ZLib
	// If Flag is 0, the file is not compressed
}

func main() {
	file, err := os.Open("file.hpi")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	header, err := ScanHPIHeader(file)
	if err != nil {
		log.Fatal(err)
	}
	TraverseTree(file, ".", int64(header.Start))
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
		entry, err := ScanHPIEntry(obj)
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
		fmt.Println(name)
		if entry.Flag == 1 {
			TraverseTree(obj, name, int64(entry.DirDataOffset))
		}
		// else {
		// ProcessFile(obj, name, int64(entry.DirDataOffset))
		// }
	}
}

// ScanHPIEntry seeks to the offset and scans the bytes from
// there into a *HPIEntry
func ScanHPIEntry(obj io.ReadSeeker) (*HPIEntry, error) {
	entry := &HPIEntry{}
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
	lr = io.LimitReader(obj, 4)
	if _, err := io.ReadFull(lr, tmp1); err != nil {
		return nil, err
	}
	entry.Flag = tmp1[0]
	return entry, nil
}

// ScanHPIHeader moves the cursor to the beginning of the file
// and then returns an HPIHeader struct
func ScanHPIHeader(obj io.ReadSeeker) (*HPIHeader, error) {
	header := &HPIHeader{
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
