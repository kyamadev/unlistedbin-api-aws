package storage

import "io"

type Storage interface {
	SaveFile(repoUUID string, fileName string, fileData io.Reader) (string, error)
	DeleteRepository(repoUUID string) error
	GetFile(repoUUID string, filePath string) ([]byte, error)
	ListDirectory(repoUUID string, dirPath string) ([]string, error)
}
