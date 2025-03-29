package controllers

import (
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

func UploadFileHandler(c *gin.Context) {
	userID, err := middleware.GetUserIDFromContext(c, DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
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
			// ストレージにファイルを保存
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

// リポジトリのコンテンツを表示するヘルパー関数
func serveRepositoryContent(c *gin.Context, repo models.Repository, urlUsername string, repoUUID string, filePath string) {
	// ファイルコンテンツの取得を試みる
	content, err := FileStorage.GetFile(repo.UUID, filePath)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{
			"username":         urlUsername,
			"repo_uuid":        repoUUID,
			"repo_name":        repo.Name,
			"filepath":         filePath,
			"data":             string(content),
			"isDirectory":      false,
			"download_allowed": repo.DownloadAllowed,
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
		"username":         urlUsername,
		"repo_uuid":        repoUUID,
		"repo_name":        repo.Name,
		"directory":        filePath,
		"entries":          entries,
		"isDirectory":      true,
		"download_allowed": repo.DownloadAllowed,
	})
}

// リポジトリのZIPダウンロードハンドラ
func ZipDownloadHandler(c *gin.Context) {
	username := c.Param("username")
	repoUUID := c.Param("uuid")

	var repo models.Repository
	if err := DB.Where("uuid = ?", repoUUID).First(&repo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found"})
		return
	}

	// 公開かつダウンロード許可があれば、誰でもダウンロード可能
	if repo.Public && repo.DownloadAllowed {
		log.Printf("公開リポジトリでダウンロード許可あり: %s", repoUUID)
	} else {
		// それ以外の場合は認証が必要で、オーナーのみがダウンロード可能

		// 認証済みかどうかをチェック（authenticated フラグが true かどうか）
		authenticated, authExists := c.Get("authenticated")
		if !authExists || authenticated != true {
			c.JSON(http.StatusForbidden, gin.H{"error": "認証が必要です"})
			return
		}

		// ユーザーIDを取得
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "ユーザー情報が取得できません"})
			return
		}

		// リポジトリのオーナー情報を取得（ユーザー名とID）
		var owner models.User
		if err := DB.Where("id = ?", repo.OwnerID).First(&owner).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ユーザー情報の取得に失敗しました"})
			return
		}

		// ユーザーIDとオーナーの照合
		if userIDVal.(string) != owner.CognitoID {
			// オーナーでないのでアクセス拒否
			c.JSON(http.StatusForbidden, gin.H{"error": "ダウンロードが許可されていません"})
			return
		}

		log.Printf("オーナーによるダウンロード: %s", repoUUID)
	}

	// ZIP作成のための一時ファイル
	tempFile, err := os.CreateTemp("", "download-*.zip")
	if err != nil {
		log.Printf("一時ファイル作成エラー: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ZIPファイルの作成に失敗しました"})
		return
	}
	defer os.Remove(tempFile.Name())

	zipWriter := zip.NewWriter(tempFile)
	defer zipWriter.Close()

	// リポジトリ全体のファイルを追加
	err = addFilesToZip(zipWriter, FileStorage, repo.UUID, "", "")
	if err != nil {
		log.Printf("リポジトリ %s のファイルをZIPに追加中にエラー: %v", repo.UUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ZIPファイルの作成に失敗しました"})
		return
	}
	entries, err := FileStorage.ListDirectory(repo.UUID, "")
	if err != nil {
		log.Printf("リポジトリ %s のディレクトリ一覧取得エラー: %v", repo.UUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リポジトリ内容の読み取りに失敗しました"})
		return
	}
	// ZIPファイルの名前を決定
	zipName := fmt.Sprintf("%s-%s.zip", username, repo.Name)
	if len(entries) == 0 {
		// リポジトリが空の場合は空のZIPファイルを作成
		zipWriter.Close()
		tempFile.Seek(0, 0)

		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
		c.Header("Content-Type", "application/zip")
		c.Stream(func(w io.Writer) bool {
			_, err := io.Copy(w, tempFile)
			if err != nil {
				log.Printf("空のZIPファイルのストリーミングエラー: %v", err)
			}
			return false
		})
		return
	}
	zipWriter.Close()

	// ファイルの先頭に移動
	tempFile.Seek(0, 0)

	// ダウンロードヘッダーを設定
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipName))
	c.Header("Content-Type", "application/zip")

	// ファイルを送信
	c.Stream(func(w io.Writer) bool {
		_, err := io.Copy(w, tempFile)
		if err != nil {
			log.Printf("Error streaming zip file: %v", err)
		}
		return false
	})
}

// ZIPファイルに再帰的にファイルを追加するヘルパー関数
func addFilesToZip(zipWriter *zip.Writer, storage storage.Storage, repoUUID, dirPath, zipPath string) error {
	// ディレクトリ内のファイル一覧を取得
	entries, err := storage.ListDirectory(repoUUID, dirPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry)
		inZipPath := filepath.Join(zipPath, entry)
		isDirectory := false

		// 1. 末尾が/で終わるものはディレクトリ
		if strings.HasSuffix(entry, "/") {
			isDirectory = true
			// 末尾の/を削除（ディレクトリパスの重複を防ぐ）
			entry = strings.TrimSuffix(entry, "/")
			fullPath = filepath.Join(dirPath, entry)
			inZipPath = filepath.Join(zipPath, entry)
		} else {
			// 2. GetFileでエラーになり、そのエラーがディレクトリであることを示す場合
			_, fileErr := storage.GetFile(repoUUID, fullPath)
			if fileErr != nil && (strings.Contains(fileErr.Error(), "is a directory") ||
				strings.Contains(fileErr.Error(), "directory")) {
				isDirectory = true
			}
		}

		if isDirectory {
			// ディレクトリの場合はZIPにディレクトリエントリを追加
			// 末尾に/を追加してディレクトリであることを明示
			_, err := zipWriter.Create(inZipPath + "/")
			if err != nil {
				return err
			}

			// 空のディレクトリエントリなので内容は書き込まない

			// 次に、ディレクトリの中身を再帰的に追加
			err = addFilesToZip(zipWriter, storage, repoUUID, fullPath, inZipPath)
			if err != nil {
				return err
			}
		} else {
			// ファイルの場合はZIPに追加
			fileContent, err := storage.GetFile(repoUUID, fullPath)
			if err != nil {
				return fmt.Errorf("ファイル %s の読み込みエラー: %w", fullPath, err)
			}

			// ZIPエントリを作成
			zipEntry, err := zipWriter.Create(inZipPath)
			if err != nil {
				return fmt.Errorf("ZIP エントリの作成エラー %s: %w", inZipPath, err)
			}

			// ファイル内容を書き込み
			_, err = zipEntry.Write(fileContent)
			if err != nil {
				return fmt.Errorf("ファイル内容の書き込みエラー %s: %w", inZipPath, err)
			}
		}
	}

	return nil
}
