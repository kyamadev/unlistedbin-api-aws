package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
)

type CognitoClient struct {
	UserPoolID             string
	UserPoolClientID       string
	IdentityProviderClient *cognito.Client
}

func NewCognitoClient(region, userPoolID, userPoolClientID string) (*CognitoClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &CognitoClient{
		UserPoolID:             userPoolID,
		UserPoolClientID:       userPoolClientID,
		IdentityProviderClient: cognito.NewFromConfig(cfg),
	}, nil
}

func (c *CognitoClient) RegisterUser(email, password, username string) (string, error) {
	signUpInput := &cognito.SignUpInput{
		ClientId: aws.String(c.UserPoolClientID),
		Username: aws.String(email), // Using email as username
		Password: aws.String(password),
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(email),
			},
			{
				Name:  aws.String("preferred_username"),
				Value: aws.String(username),
			},
		},
	}

	result, err := c.IdentityProviderClient.SignUp(context.TODO(), signUpInput)
	if err != nil {
		return "", fmt.Errorf("failed to sign up user: %v", err)
	}

	return *result.UserSub, nil
}

func (c *CognitoClient) Login(emailOrUsername, password string) (*cognito.InitiateAuthOutput, error) {
	authInput := &cognito.InitiateAuthInput{
		AuthFlow: types.AuthFlowTypeUserPasswordAuth,
		ClientId: aws.String(c.UserPoolClientID),
		AuthParameters: map[string]string{
			"USERNAME": emailOrUsername,
			"PASSWORD": password,
		},
	}

	result, err := c.IdentityProviderClient.InitiateAuth(context.TODO(), authInput)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate user: %v", err)
	}

	return result, nil
}

type CognitoAuthController struct {
	CognitoClient *CognitoClient
	DB            *gorm.DB
}

func NewCognitoAuthController(cognitoClient *CognitoClient, db *gorm.DB) *CognitoAuthController {
	return &CognitoAuthController{
		CognitoClient: cognitoClient,
		DB:            db,
	}
}

func (ctrl *CognitoAuthController) RegisterHandler(c *gin.Context) {
	var registration struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&registration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Check if username is available
	var count int64
	if err := ctrl.DB.Model(&models.User{}).Where("username = ?", registration.Username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Check if email is available
	if err := ctrl.DB.Model(&models.User{}).Where("email = ?", registration.Email).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	}

	// Register with Cognito
	userSub, err := ctrl.CognitoClient.RegisterUser(registration.Email, registration.Password, registration.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed", "details": err.Error()})
		return
	}

	// Store user in our database
	user := models.User{
		Username:  registration.Username,
		Email:     registration.Email,
		CognitoID: userSub,
	}

	if err := ctrl.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func (ctrl *CognitoAuthController) LoginHandler(c *gin.Context) {
	var login struct {
		EmailOrUsername string `json:"emailOrUsername" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Authenticate with Cognito
	authResult, err := ctrl.CognitoClient.Login(login.EmailOrUsername, login.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// Return tokens to client
	c.JSON(http.StatusOK, gin.H{
		"message":       "Logged in successfully",
		"token":         authResult.AuthenticationResult.IdToken,
		"refresh_token": authResult.AuthenticationResult.RefreshToken,
		"expires_in":    authResult.AuthenticationResult.ExpiresIn,
	})
}

func (ctrl *CognitoAuthController) LogoutHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication token required"})
		return
	}

	var logoutReq struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&logoutReq); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully (token will expire naturally)"})
		return
	}

	_, err := ctrl.CognitoClient.IdentityProviderClient.RevokeToken(context.TODO(), &cognito.RevokeTokenInput{
		ClientId: aws.String(ctrl.CognitoClient.UserPoolClientID),
		Token:    aws.String(logoutReq.RefreshToken),
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to revoke refresh token",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (ctrl *CognitoAuthController) CheckUsernameAvailability(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	var count int64
	if err := ctrl.DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	available := count == 0
	c.JSON(http.StatusOK, gin.H{"available": available})
}

func (ctrl *CognitoAuthController) UpdateUsernameHandler(c *gin.Context) {
	user, err := middleware.GetUserFromContext(c, ctrl.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	// Parse request
	var payload struct {
		NewUsername string `json:"newUsername" binding:"required"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: newUsername required"})
		return
	}

	// Check if new username is available
	var count int64
	if err := ctrl.DB.Model(&models.User{}).Where("username = ?", payload.NewUsername).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// Update username in Cognito
	updateAttributesInput := &cognito.AdminUpdateUserAttributesInput{
		UserPoolId: aws.String(ctrl.CognitoClient.UserPoolID),
		Username:   aws.String(user.Email), // Use email as username in Cognito
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("preferred_username"),
				Value: aws.String(payload.NewUsername),
			},
		},
	}

	_, err = ctrl.CognitoClient.IdentityProviderClient.AdminUpdateUserAttributes(context.TODO(), updateAttributesInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update username in Cognito",
			"details": err.Error(),
		})
		return
	}

	// Update username in database
	user.Username = payload.NewUsername
	if err := ctrl.DB.Save(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update username in database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Username updated successfully",
		"username": user.Username,
	})
}

func (ctrl *CognitoAuthController) DeleteAccountHandler(c *gin.Context) {
	user, err := middleware.GetUserFromContext(c, ctrl.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	// Find all repositories owned by the user
	var repos []models.Repository
	if err := ctrl.DB.Where("owner_id = ?", user.ID).Find(&repos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve repositories"})
		return
	}

	// Delete repositories from storage and database
	for _, repo := range repos {
		if err := ctrl.DB.Delete(&repo).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete repository: " + repo.UUID})
			return
		}

		if err := FileStorage.DeleteRepository(repo.UUID); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":   "Account deleted but failed to remove files for repository: " + repo.UUID,
				"repo_uuid": repo.UUID,
			})
			return
		}
	}

	// Delete user from Cognito
	deleteUserInput := &cognito.AdminDeleteUserInput{
		UserPoolId: aws.String(ctrl.CognitoClient.UserPoolID),
		Username:   aws.String(user.Email), // Use email as username in Cognito
	}

	_, err = ctrl.CognitoClient.IdentityProviderClient.AdminDeleteUser(context.TODO(), deleteUserInput)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete user from Cognito",
			"details": err.Error(),
		})
		return
	}

	// Delete user from our database
	if err := ctrl.DB.Unscoped().Delete(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "User deleted from Cognito but failed to delete from database",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account and all repositories deleted successfully"})
}
