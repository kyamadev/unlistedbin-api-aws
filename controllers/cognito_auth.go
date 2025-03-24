package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	appConfig "Unlistedbin-api/config"
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

	userSub, err := ctrl.CognitoClient.RegisterUser(registration.Email, registration.Password, registration.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed", "details": err.Error()})
		return
	}
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
		ClientType      string `json:"clientType"` // "web" or "mobile"
	}

	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	authResult, err := ctrl.CognitoClient.Login(login.EmailOrUsername, login.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	clientType := login.ClientType
	if clientType == "" {
		userAgent := c.GetHeader("User-Agent")
		if strings.Contains(userAgent, "Mobile") ||
			strings.Contains(userAgent, "Android") ||
			strings.Contains(userAgent, "iOS") {
			clientType = "mobile"
		} else {
			clientType = "web"
		}
	}

	if clientType != "mobile" {
		domain := ""
		secure := false
		if appConfig.AppConfig.Env == "production" {
			secure = true
			domain = appConfig.AppConfig.CookieDomain
		}

		// XSS対策
		sameSite := http.SameSiteLaxMode
		if appConfig.AppConfig.Env == "production" {
			sameSite = http.SameSiteStrictMode
		}

		c.SetSameSite(sameSite)
		c.SetCookie(
			"id_token",
			*authResult.AuthenticationResult.IdToken,
			int(authResult.AuthenticationResult.ExpiresIn),
			"/",
			domain,
			secure,
			true, // HTTPOnly
		)

		c.SetSameSite(sameSite)
		c.SetCookie(
			"refresh_token",
			*authResult.AuthenticationResult.RefreshToken,
			60*60*24*30, // 30days
			"/",
			domain,
			secure,
			true, // HTTPOnly
		)

		c.JSON(http.StatusOK, gin.H{
			"message": "Logged in successfully",
			"status":  "success",
		})
		return
	}

	// モバイルクライアントの場合のみトークン情報を返す
	expiresAt := time.Now().Add(time.Duration(authResult.AuthenticationResult.ExpiresIn) * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"message":       "Logged in successfully",
		"token":         authResult.AuthenticationResult.IdToken,
		"refresh_token": authResult.AuthenticationResult.RefreshToken,
		"expires_in":    authResult.AuthenticationResult.ExpiresIn,
		"expires_at":    expiresAt.Format(time.RFC3339),
	})
}

func (ctrl *CognitoAuthController) LogoutHandler(c *gin.Context) {
	var refreshToken string
	var logoutReq struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&logoutReq); err == nil && logoutReq.RefreshToken != "" {
		refreshToken = logoutReq.RefreshToken
	} else {
		cookieToken, err := c.Cookie("refresh_token")
		if err == nil {
			refreshToken = cookieToken
		}
	}

	if refreshToken != "" {
		_, err := ctrl.CognitoClient.IdentityProviderClient.RevokeToken(context.TODO(), &cognito.RevokeTokenInput{
			ClientId: aws.String(ctrl.CognitoClient.UserPoolClientID),
			Token:    aws.String(refreshToken),
		})

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"warning": "Failed to revoke refresh token, but cookies have been cleared",
				"details": err.Error(),
			})
		}
	}

	domain := ""
	secure := false
	if appConfig.AppConfig.Env == "production" {
		secure = true
		domain = appConfig.AppConfig.CookieDomain
	}

	sameSite := http.SameSiteLaxMode
	if appConfig.AppConfig.Env == "production" {
		sameSite = http.SameSiteStrictMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie("id_token", "", -1, "/", domain, secure, true)

	c.SetSameSite(sameSite)
	c.SetCookie("refresh_token", "", -1, "/", domain, secure, true)

	c.SetSameSite(sameSite)
	c.SetCookie("csrf_token", "", -1, "/", domain, secure, false)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (ctrl *CognitoAuthController) GetUserInfoHandler(c *gin.Context) {
	user, err := middleware.GetUserFromContext(c, ctrl.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

func (ctrl *CognitoAuthController) ConfirmSignUpHandler(c *gin.Context) {
	var confirm struct {
		Username         string `json:"username" binding:"required"`
		ConfirmationCode string `json:"confirmationCode" binding:"required"`
	}

	if err := c.ShouldBindJSON(&confirm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	confirmSignUpInput := &cognito.ConfirmSignUpInput{
		ClientId:         aws.String(ctrl.CognitoClient.UserPoolClientID),
		Username:         aws.String(confirm.Username),
		ConfirmationCode: aws.String(confirm.ConfirmationCode),
	}

	_, err := ctrl.CognitoClient.IdentityProviderClient.ConfirmSignUp(context.TODO(), confirmSignUpInput)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to confirm signup",
			"details": err.Error(),
		})
		return
	}

	var user models.User
	if err := ctrl.DB.Where("username = ? OR email = ?", confirm.Username, confirm.Username).First(&user).Error; err == nil {
		user.EmailVerified = true
		ctrl.DB.Save(&user)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signup confirmed successfully"})
}

func (ctrl *CognitoAuthController) ResetPasswordHandler(c *gin.Context) {
	var reset struct {
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&reset); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	forgotPasswordInput := &cognito.ForgotPasswordInput{
		ClientId: aws.String(ctrl.CognitoClient.UserPoolClientID),
		Username: aws.String(reset.Username),
	}

	result, err := ctrl.CognitoClient.IdentityProviderClient.ForgotPassword(context.TODO(), forgotPasswordInput)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to request password reset",
			"details": err.Error(),
		})
		return
	}

	var destination string
	if result.CodeDeliveryDetails != nil && result.CodeDeliveryDetails.Destination != nil {
		destination = *result.CodeDeliveryDetails.Destination
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Reset code sent successfully",
		"destination": destination,
	})
}

func (ctrl *CognitoAuthController) ConfirmResetPasswordHandler(c *gin.Context) {
	var confirm struct {
		Username         string `json:"username" binding:"required"`
		ConfirmationCode string `json:"confirmationCode" binding:"required"`
		NewPassword      string `json:"newPassword" binding:"required"`
	}

	if err := c.ShouldBindJSON(&confirm); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	confirmForgotPasswordInput := &cognito.ConfirmForgotPasswordInput{
		ClientId:         aws.String(ctrl.CognitoClient.UserPoolClientID),
		Username:         aws.String(confirm.Username),
		ConfirmationCode: aws.String(confirm.ConfirmationCode),
		Password:         aws.String(confirm.NewPassword),
	}

	_, err := ctrl.CognitoClient.IdentityProviderClient.ConfirmForgotPassword(context.TODO(), confirmForgotPasswordInput)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to reset password",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

func (ctrl *CognitoAuthController) ChangePasswordHandler(c *gin.Context) {
	var change struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}

	if err := c.ShouldBindJSON(&change); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if _, err := middleware.GetUserFromContext(c, ctrl.DB); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	idToken, cookieErr := c.Cookie("id_token")

	if cookieErr != nil {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Authentication token required"})
			return
		}
		idToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	changePasswordInput := &cognito.ChangePasswordInput{
		AccessToken:      aws.String(idToken),
		PreviousPassword: aws.String(change.OldPassword),
		ProposedPassword: aws.String(change.NewPassword),
	}

	_, err := ctrl.CognitoClient.IdentityProviderClient.ChangePassword(context.TODO(), changePasswordInput)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to change password",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
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

	domain := ""
	secure := false
	if appConfig.AppConfig.Env == "production" {
		secure = true
		domain = appConfig.AppConfig.CookieDomain
	}

	sameSite := http.SameSiteLaxMode
	if appConfig.AppConfig.Env == "production" {
		sameSite = http.SameSiteStrictMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie("id_token", "", -1, "/", domain, secure, true)

	c.SetSameSite(sameSite)
	c.SetCookie("refresh_token", "", -1, "/", domain, secure, true)

	c.SetSameSite(sameSite)
	c.SetCookie("csrf_token", "", -1, "/", domain, secure, false)

	c.JSON(http.StatusOK, gin.H{"message": "Account and all repositories deleted successfully"})
}
