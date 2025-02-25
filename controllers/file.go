package controllers

import (
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

var FileStorage storage.Storage

func UploadFileHandler(c *gin.Context) {
	session := sessions.Default(c)
	userIDVal := session.Get("userID")
	if userIDVal == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	ownerID := userIDVal.(uint)

	repoName := c.PostForm("repository_name")
	if repoName == "" {
		repoName = "New Repository"
	}
	publicFlag := c.PostForm("public") == "true"

	// サーバー側で新規リポジトリを生成
	newRepo := models.Repository{
		OwnerID: ownerID,
		Name:    repoName,
		Public:  publicFlag,
	}
	if err := DB.Create(&newRepo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repository"})
		return
	}

	// ファイルアップロード処理
	zipFile, errZip := c.FormFile("zip_file")
	if errZip == nil {
		// ZIPファイルアップロード処理
		src, err := zipFile.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open zip file"})
			return
		}
		defer src.Close()
		// 大容量対応：一時ファイルにストリームコピーする
		tempFile, err := os.CreateTemp("", "upload-*.zip")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp file"})
			return
		}
		// 後で一時ファイルを削除するためのdefer
		defer func() {
			tempFile.Close()
			os.Remove(tempFile.Name())
		}()

		// ZIPファイルの内容を一時ファイルにコピー（ストリーム処理）
		if _, err := io.Copy(tempFile, src); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to copy zip file to temp file"})
			return
		}

		// 一時ファイルのサイズ取得
		fi, err := tempFile.Stat()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get temp file info"})
			return
		}

		// 一時ファイルの先頭にシーク
		if _, err := tempFile.Seek(0, 0); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to seek temp file"})
			return
		}

		// ZIPリーダー
		zipReader, err := zip.NewReader(tempFile, fi.Size())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create zip reader"})
			return
		}

		// ZIP内の各ファイルを処理
		for _, f := range zipReader.File {
			if f.FileInfo().IsDir() {
				continue
			}
			fr, err := f.Open()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to open file in zip: %s", f.Name)})
				return
			}
			// ストレージにファイルを保存（repoUUID は newRepo.UUID）
			savedPath, err := FileStorage.SaveFile(newRepo.UUID, f.Name, fr)
			fr.Close()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file: %s", f.Name)})
				return
			}
			// DBにファイル情報を保存
			newFile := models.File{
				RepositoryID: newRepo.ID,
				FileName:     f.Name,
				FilePath:     savedPath,
			}
			if err := DB.Create(&newFile).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file record for: %s", f.Name)})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "ZIP upload and extraction successful", "repo_uuid": newRepo.UUID})
		return
	}

	// ZIPファイルがなければ、単一ファイルアップロード処理
	singleFile, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File not found"})
		return
	}
	fr, err := singleFile.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file"})
		return
	}
	defer fr.Close()

	filePath, err := FileStorage.SaveFile(newRepo.UUID, singleFile.Filename, fr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "File upload failed"})
		return
	}
	newFile := models.File{
		RepositoryID: newRepo.ID,
		FileName:     singleFile.Filename,
		FilePath:     filePath,
	}
	if err := DB.Create(&newFile).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file record"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "repo_uuid": newRepo.UUID})
}
func FileViewerHandler(c *gin.Context) {
	urlUsername := c.Param("username")
	repoUUID := c.Param("uuid")
	filePath := c.Param("filepath") // キャッチオールパラメータ。先頭に "/" が含まれる場合があるため除去
	if len(filePath) > 0 && filePath[0] == '/' {
		filePath = filePath[1:]
	}

	var repo models.Repository
	if err := DB.Where("uuid = ?", repoUUID).First(&repo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found"})
		return
	}

	// 公開設定lookup
	if !repo.Public {
		session := sessions.Default(c)
		sessUsername := session.Get("username")
		if sessUsername == nil || sessUsername.(string) != urlUsername {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Access denied"})
			return
		}
	}

	content, err := FileStorage.GetFile(repo.UUID, filePath)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{
			"username":    urlUsername,
			"repo_uuid":   repoUUID,
			"filepath":    filePath,
			"data":        string(content),
			"isDirectory": false,
		})
		return
	}

	// ファイルとして取得できなかった場合、ディレクトリとみなして ListDirectory を利用
	entries, errDir := FileStorage.ListDirectory(repo.UUID, filePath)
	if errDir != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File or directory not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"username":    urlUsername,
		"repo_uuid":   repoUUID,
		"directory":   filePath,
		"entries":     entries,
		"isDirectory": true,
	})
}
