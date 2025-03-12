package storage

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Storage struct {
	client *s3.Client
	bucket string
	region string
}

func NewS3Storage(region, bucket string) (*S3Storage, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg)

	return &S3Storage{
		client: client,
		bucket: bucket,
		region: region,
	}, nil
}

func (s *S3Storage) SaveFile(repoUUID, fileName string, fileData io.Reader) (string, error) {
	data, err := io.ReadAll(fileData)
	if err != nil {
		return "", err
	}

	key := filepath.Join(repoUUID, fileName)

	key = strings.ReplaceAll(key, "\\", "/")

	// Upload to S3
	_, err = s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})

	if err != nil {
		return "", err
	}

	return "s3://" + s.bucket + "/" + key, nil
}

func (s *S3Storage) GetFile(repoUUID, filePath string) ([]byte, error) {
	key := filepath.Join(repoUUID, filePath)

	key = strings.ReplaceAll(key, "\\", "/")

	resp, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func (s *S3Storage) DeleteRepository(repoUUID string) error {
	// List all objects with the prefix
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(repoUUID + "/"),
	})

	// Delete each object
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return err
		}

		for _, obj := range page.Contents {
			_, err = s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(s.bucket),
				Key:    obj.Key,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *S3Storage) ListDirectory(repoUUID, dirPath string) ([]string, error) {
	prefix := filepath.Join(repoUUID, dirPath)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	// Fix path separator for S3 (use forward slashes)
	prefix = strings.ReplaceAll(prefix, "\\", "/")

	// List objects with the prefix
	resp, err := s.client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:    aws.String(s.bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"), // Use delimiter to list directories
	})

	if err != nil {
		return nil, err
	}

	var entries []string

	// Add files
	for _, obj := range resp.Contents {
		// Extract just the filename from the key
		key := *obj.Key
		if key == prefix {
			continue // Skip the directory itself
		}
		name := strings.TrimPrefix(key, prefix)
		if name != "" {
			entries = append(entries, name)
		}
	}

	// Add subdirectories
	for _, cp := range resp.CommonPrefixes {
		dir := *cp.Prefix
		dir = strings.TrimPrefix(dir, prefix)
		dir = strings.TrimSuffix(dir, "/")
		if dir != "" {
			entries = append(entries, dir+"/")
		}
	}

	return entries, nil
}
