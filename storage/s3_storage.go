package storage

import (
	"errors"
	"fmt"
	"io"
)

// S3向けのダミー実装
type S3Storage struct {
	Bucket string
}

func NewS3Storage(bucket string) *S3Storage {
	return &S3Storage{Bucket: bucket}
}

func (s *S3Storage) SaveFile(repoUUID, fileName string, fileData io.Reader) (string, error) {
	_, err := io.Copy(io.Discard, fileData)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://%s.s3.amazonaws.com/%s/%s", s.Bucket, repoUUID, fileName)
	return url, nil
}

func (s *S3Storage) DeleteRepository(repoUUID string) error {
	fmt.Printf("Simulated deletion of repository %s in S3\n", repoUUID)
	return nil
}

func (s *S3Storage) GetFile(repoUUID string, filePath string) ([]byte, error) {

	return nil, errors.New("GetFile not implemented for S3Storage")
}

func (s *S3Storage) ListDirectory(repoUUID string, dirPath string) ([]string, error) {
	return nil, errors.New("ListDirectory not implemented for S3Storage")
}
