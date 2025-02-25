package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type LocalStorage struct {
	BasePath string
}

func NewLocalStorage(basePath string) *LocalStorage {
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		absPath = basePath
	}
	os.MkdirAll(absPath, os.ModePerm)
	return &LocalStorage{BasePath: absPath}
}

func (ls *LocalStorage) SaveFile(repoUUID, fileName string, fileData io.Reader) (string, error) {
	destDir := filepath.Join(ls.BasePath, repoUUID, filepath.Dir(fileName))
	fmt.Printf("Creating directory: %s\n", destDir)
	if err := os.MkdirAll(destDir, os.ModePerm); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, filepath.Base(fileName))
	fmt.Printf("Saving file to: %s\n", dest)
	out, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, fileData); err != nil {
		return "", err
	}
	return dest, nil
}

func (ls *LocalStorage) DeleteRepository(repoUUID string) error {
	repoDir := filepath.Join(ls.BasePath, repoUUID)
	fmt.Printf("Deleting repository directory: %s\n", repoDir)
	return os.RemoveAll(repoDir)
}

func (ls *LocalStorage) GetFile(repoUUID string, filePath string) ([]byte, error) {
	fullPath := filepath.Join(ls.BasePath, repoUUID, filePath)
	return os.ReadFile(fullPath)
}

func (ls *LocalStorage) ListDirectory(repoUUID string, dirPath string) ([]string, error) {
	fullPath := filepath.Join(ls.BasePath, repoUUID, dirPath)
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}
