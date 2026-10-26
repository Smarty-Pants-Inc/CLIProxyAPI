package management

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// Cursor positions, sizes and fingerprints always describe uncompressed bytes.
// Ordinary logs keep their original on-disk ReaderAt path. Compressed backups
// are bounded by lumberjack's 10 MiB rotation size and can be read into memory.
type logReadFile interface {
	io.Reader
	io.ReaderAt
	Stat() (os.FileInfo, error)
	Close() error
}

type memoryLogFile struct {
	*bytes.Reader
	info os.FileInfo
}

type uncompressedLogInfo struct {
	os.FileInfo
	size int64
}

func (i uncompressedLogInfo) Size() int64           { return i.size }
func (f *memoryLogFile) Stat() (os.FileInfo, error) { return f.info, nil }
func (f *memoryLogFile) Close() error               { return nil }

func openLogReadFile(path string) (logReadFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return file, nil
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	const maxBackupBytes = 10 << 20
	data, err := io.ReadAll(io.LimitReader(zr, maxBackupBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBackupBytes {
		return nil, fmt.Errorf("compressed log exceeds %d uncompressed bytes", maxBackupBytes)
	}
	return &memoryLogFile{Reader: bytes.NewReader(data), info: uncompressedLogInfo{FileInfo: info, size: int64(len(data))}}, nil
}

func logReadFileInfo(path string) (os.FileInfo, error) {
	if !strings.HasSuffix(path, ".gz") {
		return os.Stat(path)
	}
	file, err := openLogReadFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Stat()
}
