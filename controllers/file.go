package controllers

import (
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func UploadFileHandler(c *gin.Context) {
	userID, err := middleware.GetUserIDFromContext(c, DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	// ユーザーのストレージ情報を取得
	var user models.User
	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
		return
	}

	// ストレージ制限が未設定なら設定
	if user.StorageLimit == 0 {
		user.StorageLimit = models.DefaultStorageLimit
		DB.Save(&user)
	}

	repoName := c.PostForm("repository_name")
	if repoName == "" {
		repoName = "New Repository"
	}
	publicFlag := c.PostForm("public") == "true"

	newRepo := models.Repository{
		OwnerID: userID,
		Name:    repoName,
		Public:  publicFlag,
	}
	if err := DB.Create(&newRepo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create repository"})
		return
	}

	// アップロードに関連するファイルの合計サイズを計算するための変数
	var totalFileSize int64 = 0

	// ファイルアップロード処理
	zipFile, errZip := c.FormFile("zip_file")
	if errZip == nil {
		// ZIPファイルのサイズをチェック
		zipFileSize := zipFile.Size

		// 一時的に容量チェック（ZIP展開後のサイズは予測が難しいため、安全に見積もる）
		// 圧縮率を考慮して3倍のサイズと仮定
		estimatedExtractedSize := zipFileSize * 3

		// 容量制限チェック
		if user.HasReachedStorageLimit(estimatedExtractedSize) {
			DB.Delete(&newRepo) // 作成したリポジトリを削除
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Storage limit exceeded. You have %d bytes remaining.", user.RemainingStorage()),
			})
			return
		}

		// 以下、ZIPファイル処理の既存コード
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

		// 実際のファイルサイズの合計を計算
		var actualTotalSize int64 = 0
		for _, f := range zipReader.File {
			if f.FileInfo().IsDir() {
				continue
			}
			actualTotalSize += int64(f.UncompressedSize64)
		}

		// 実際のサイズで再度容量チェック
		if user.HasReachedStorageLimit(actualTotalSize) {
			DB.Delete(&newRepo) // 作成したリポジトリを削除
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("Storage limit exceeded. Files in ZIP require %d bytes, but you only have %d bytes available.",
					actualTotalSize, user.RemainingStorage()),
			})
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

			// ストレージにファイルを保存
			savedPath, err := FileStorage.SaveFile(newRepo.UUID, f.Name, fr)
			fr.Close()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file: %s", f.Name)})
				return
			}

			// ファイルのサイズを取得
			fileSize := int64(f.UncompressedSize64)
			totalFileSize += fileSize

			// DBにファイル情報を保存
			newFile := models.File{
				RepositoryID: newRepo.ID,
				FileName:     f.Name,
				FilePath:     savedPath,
				FileSize:     fileSize,
			}
			if err := DB.Create(&newFile).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save file record for: %s", f.Name)})
				return
			}
		}

		// ユーザーのストレージ使用量を更新
		user.StorageUsed += totalFileSize
		if err := DB.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user storage usage"})
			return
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

	// 単一ファイルのサイズを取得
	fileSize := singleFile.Size

	// 容量制限をチェック
	if user.HasReachedStorageLimit(fileSize) {
		DB.Delete(&newRepo) // 作成したリポジトリを削除
		c.JSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Storage limit exceeded. File size: %d bytes, Available: %d bytes",
				fileSize, user.RemainingStorage()),
		})
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
		FileSize:     fileSize,
	}
	if err := DB.Create(&newFile).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file record"})
		return
	}

	// ユーザーのストレージ使用量を更新
	user.StorageUsed += fileSize
	if err := DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user storage usage"})
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

	if repo.Public {
		c.Header("X-Robots-Tag", "noindex, nofollow")
		serveRepositoryContent(c, repo, urlUsername, repoUUID, filePath)
		return
	}

	// 非公開リポジトリの場合はアクセス制御

	// 認証チェック
	authenticatedVal, authenticated := c.Get("authenticated")
	if !authenticated || authenticatedVal != true {
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Authentication required"})
		return
	}

	// まず所有権のチェック - 所有者なら常にアクセス可能
	userIDVal, userIDExists := c.Get("userID")
	if userIDExists {
		var user models.User
		if err := DB.Where("cognito_id = ?", userIDVal).First(&user).Error; err == nil {
			if user.ID == repo.OwnerID {
				// リポジトリ所有者なのでアクセス許可
				serveRepositoryContent(c, repo, urlUsername, repoUUID, filePath)
				return
			}
		}
	}

	// 所有者でない場合はURLユーザー名との一致をチェック
	usernameVal, exists := c.Get("username")
	if !exists || usernameVal.(string) != urlUsername {
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: Access denied"})
		return
	}

	// 上記チェックをすべて通過した場合、コンテンツを表示
	serveRepositoryContent(c, repo, urlUsername, repoUUID, filePath)
}

// コンテンツを返す関数を分離して処理をシンプルに
func serveRepositoryContent(c *gin.Context, repo models.Repository, urlUsername string, repoUUID string, filePath string) {
	// ファイルコンテンツの取得を試みる
	content, err := FileStorage.GetFile(repo.UUID, filePath)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{
			"username":    urlUsername,
			"repo_uuid":   repoUUID,
			"repo_name":   repo.Name,
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
		"repo_name":   repo.Name,
		"directory":   filePath,
		"entries":     entries,
		"isDirectory": true,
	})
}
