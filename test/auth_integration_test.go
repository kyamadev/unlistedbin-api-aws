package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"Unlistedbin-api/controllers"
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/test/testutils"
)

func TestUserRegistrationAndLogin(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration test")
	}

	env := testutils.SetupTestEnvironment(t)
	defer testutils.CleanupTestEnvironment(env)

	timestamp := time.Now().Unix()
	testEmail := fmt.Sprintf("test+%d@example.com", timestamp)
	testUsername := fmt.Sprintf("testuser%d", timestamp)
	testPassword := "TestPassword123!"

	authController := controllers.NewCognitoAuthController(env.CognitoClient, env.DB)

	env.Router.POST("/api/auth/register", authController.RegisterHandler)
	env.Router.POST("/api/auth/login", authController.LoginHandler)
	env.Router.POST("/api/auth/logout", middleware.JWTAuthMiddleware(env.JWTValidator), authController.LogoutHandler)

	t.Run("Register", func(t *testing.T) {
		reqBody := map[string]string{
			"email":    testEmail,
			"password": testPassword,
			"username": testUsername,
		}

		jsonData, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Registration successful", response["message"])

		var user models.User
		result := env.DB.Where("email = ?", testEmail).First(&user)
		assert.Nil(t, result.Error)
		assert.Equal(t, testUsername, user.Username)
		assert.NotEmpty(t, user.CognitoID)
	})

	var idToken, refreshToken string

	t.Run("Login", func(t *testing.T) {
		reqBody := map[string]string{
			"emailOrUsername": testEmail,
			"password":        testPassword,
		}

		jsonData, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Logged in successfully", response["message"])
		assert.NotNil(t, response["token"])
		assert.NotNil(t, response["refresh_token"])

		idToken = response["token"].(string)
		refreshToken = response["refresh_token"].(string)
	})

	t.Run("Logout", func(t *testing.T) {
		reqBody := map[string]string{
			"refresh_token": refreshToken,
		}

		jsonData, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/auth/logout", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+idToken)

		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Logged out successfully", response["message"])
	})
}

func TestRepositoryOperationsWithAuth(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration test")
	}

	env := testutils.SetupTestEnvironment(t)
	defer testutils.CleanupTestEnvironment(env)

	timestamp := time.Now().Unix()
	testEmail := fmt.Sprintf("test+%d@example.com", timestamp)
	testUsername := fmt.Sprintf("testuser%d", timestamp)
	testPassword := "TestPassword123!"

	testUser := createTestUser(t, env, testEmail, testUsername, testPassword)

	authController := controllers.NewCognitoAuthController(env.CognitoClient, env.DB)
	env.Router.POST("/api/auth/login", authController.LoginHandler)

	repoGroup := env.Router.Group("/api")
	repoGroup.Use(middleware.JWTAuthMiddleware(env.JWTValidator))
	repoGroup.GET("/repositories", controllers.GetRepositories)
	repoGroup.POST("/repositories", controllers.CreateRepository)

	idToken := loginAndGetToken(t, env, testEmail, testPassword)

	t.Run("CreateRepository", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"name":   "Test Repository",
			"public": true,
		}

		jsonData, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/repositories", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+idToken)

		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response models.Repository
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Test Repository", response.Name)
		assert.Equal(t, true, response.Public)
		assert.Equal(t, testUser.ID, response.OwnerID)
		assert.NotEmpty(t, response.UUID)
	})

	t.Run("GetRepositories", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/repositories", nil)
		req.Header.Set("Authorization", "Bearer "+idToken)

		w := httptest.NewRecorder()
		env.Router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var repositories []models.Repository
		json.Unmarshal(w.Body.Bytes(), &repositories)
		assert.Equal(t, 1, len(repositories))
		assert.Equal(t, "Test Repository", repositories[0].Name)
		assert.Equal(t, true, repositories[0].Public)
		assert.Equal(t, testUser.ID, repositories[0].OwnerID)
	})
}

func createTestUser(t *testing.T, env *testutils.TestEnv, email, username, password string) *models.User {
	userSub, err := env.CognitoClient.RegisterUser(email, password, username)
	if err != nil {
		t.Fatalf("Failed to create test user in Cognito: %v", err)
	}

	user := models.User{
		Username:  username,
		Email:     email,
		CognitoID: userSub,
	}

	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("Failed to create test user in database: %v", err)
	}

	return &user
}

func loginAndGetToken(t *testing.T, env *testutils.TestEnv, email, password string) string {
	reqBody := map[string]string{
		"emailOrUsername": email,
		"password":        password,
	}

	jsonData, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	env.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to login: %s", w.Body.String())
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	return response["token"].(string)
}
