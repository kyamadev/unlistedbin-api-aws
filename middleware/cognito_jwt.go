package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type JWKS struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		E   string `json:"e"`
		N   string `json:"n"`
		Use string `json:"use"`
		Alg string `json:"alg"`
	} `json:"keys"`
}

type CognitoClaims struct {
	jwt.RegisteredClaims
	TokenUse      string                 `json:"token_use"`
	Username      string                 `json:"username"`
	ClientID      string                 `json:"client_id"`
	CognitoGroups []string               `json:"cognito:groups"`
	Email         string                 `json:"email"`
	Custom        map[string]interface{} `json:"-"`
}

type CognitoJWTValidator struct {
	Region        string
	UserPoolID    string
	ClientID      string
	jwksURL       string
	jwks          map[string]*rsa.PublicKey
	jwksLock      sync.RWMutex
	jwksLastFetch time.Time
	jwksRefresh   time.Duration
}

func NewCognitoJWTValidator(region, userPoolID, clientID string) *CognitoJWTValidator {
	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolID)

	return &CognitoJWTValidator{
		Region:      region,
		UserPoolID:  userPoolID,
		ClientID:    clientID,
		jwksURL:     jwksURL,
		jwks:        make(map[string]*rsa.PublicKey),
		jwksRefresh: 24 * time.Hour,
	}
}

func (v *CognitoJWTValidator) FetchJWKS() error {
	v.jwksLock.Lock()
	defer v.jwksLock.Unlock()

	if len(v.jwks) > 0 && time.Since(v.jwksLastFetch) < v.jwksRefresh {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status code %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	newJWKS := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || key.Use != "sig" {
			continue
		}

		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		var exponent int
		if len(e) == 3 {
			exponent = int(e[0])<<16 | int(e[1])<<8 | int(e[2])
		} else if len(e) == 2 {
			exponent = int(e[0])<<8 | int(e[1])
		} else if len(e) == 1 {
			exponent = int(e[0])
		} else {
			continue
		}

		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: exponent,
		}

		newJWKS[key.Kid] = publicKey
	}

	v.jwks = newJWKS
	v.jwksLastFetch = time.Now()
	return nil
}

func (v *CognitoJWTValidator) ValidateToken(tokenString string) (*CognitoClaims, error) {
	if err := v.FetchJWKS(); err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &CognitoClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kidInterface, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("no key ID (kid) in token header")
		}
		kid, ok := kidInterface.(string)
		if !ok {
			return nil, errors.New("key ID (kid) is not a string")
		}

		v.jwksLock.RLock()
		defer v.jwksLock.RUnlock()
		publicKey, ok := v.jwks[kid]
		if !ok {
			return nil, fmt.Errorf("no public key found for kid: %s", kid)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse or validate token: %w", err)
	}

	claims, ok := token.Claims.(*CognitoClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", v.Region, v.UserPoolID)
	issuer, err := claims.GetIssuer()
	if err != nil || issuer != expectedIssuer {
		return nil, errors.New("invalid issuer")
	}

	if claims.TokenUse != "id" && claims.TokenUse != "access" {
		return nil, errors.New("invalid token use")
	}

	audience, err := claims.GetAudience()
	if err != nil {
		return nil, errors.New("invalid audience")
	}

	if claims.TokenUse == "id" && (len(audience) == 0 || audience[0] != v.ClientID) {
		return nil, errors.New("invalid audience")
	}

	if claims.TokenUse == "access" && claims.ClientID != v.ClientID {
		return nil, errors.New("invalid client ID")
	}

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		return nil, errors.New("invalid expiration time")
	}
	if expirationTime == nil || expirationTime.Before(time.Now()) {
		return nil, errors.New("token is expired")
	}

	return claims, nil
}

func (v *CognitoJWTValidator) ParseAndValidateToken(authHeader string) (*CognitoClaims, error) {
	if authHeader == "" {
		return nil, errors.New("authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}
	tokenString := parts[1]

	return v.ValidateToken(tokenString)
}

func (v *CognitoJWTValidator) VerifyTokenWithContext(ctx context.Context, authHeader string) (*CognitoClaims, error) {
	if authHeader == "" {
		return nil, errors.New("authorization header is missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}
	tokenString := parts[1]

	type result struct {
		claims *CognitoClaims
		err    error
	}
	resultCh := make(chan result, 1)

	go func() {
		claims, err := v.ValidateToken(tokenString)
		resultCh <- result{claims, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		return res.claims, res.err
	}
}

func JWTAuthMiddleware(validator *CognitoJWTValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string
		var tokenSource string

		tokenCookie, cookieErr := c.Cookie("id_token")
		if cookieErr == nil && tokenCookie != "" {
			tokenStr = tokenCookie
			tokenSource = "cookie"
		}

		authHeader := c.GetHeader("Authorization")
		if tokenSource == "" && authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			tokenSource = "header"
		}
		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Authentication required",
				"detail": "No valid authentication token found",
			})
			c.Abort()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		claims, err := validator.VerifyTokenWithContext(ctx, tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid or expired token",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		subject, _ := claims.GetSubject()
		c.Set("userID", subject)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("tokenSource", tokenSource) // トークンのソースを記録（デバッグ用）

		if len(claims.CognitoGroups) > 0 {
			c.Set("userGroups", claims.CognitoGroups)
		}

		c.Next()
	}
}

func OptionalJWTAuthMiddleware(validator *CognitoJWTValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string
		var tokenSource string

		tokenCookie, cookieErr := c.Cookie("id_token")
		if cookieErr == nil && tokenCookie != "" {
			tokenStr = tokenCookie
			tokenSource = "cookie"
		}

		authHeader := c.GetHeader("Authorization")
		if tokenSource == "" && authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			tokenSource = "header"
		}

		if tokenStr == "" {
			c.Next()
			return
		}

		claims, err := validator.ValidateToken(tokenStr)
		if err != nil {
			// 無効なトークンでも続行
			c.Next()
			return
		}

		subject, _ := claims.GetSubject()
		c.Set("userID", subject)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("authenticated", true)
		c.Set("tokenSource", tokenSource)

		if len(claims.CognitoGroups) > 0 {
			c.Set("userGroups", claims.CognitoGroups)
		}

		c.Next()
	}
}

func RefreshTokenMiddleware(cognitoClient *cognito.Client, clientID string) gin.HandlerFunc {
	return func(c *gin.Context) {

		idToken, err := c.Cookie("id_token")
		if err != nil {
			c.Next()
			return
		}

		token, _, err := new(jwt.Parser).ParseUnverified(idToken, &CognitoClaims{})
		if err != nil {
			c.Next()
			return
		}

		claims, ok := token.Claims.(*CognitoClaims)
		if !ok {
			c.Next()
			return
		}

		expirationTime, err := claims.GetExpirationTime()
		if err != nil || expirationTime == nil {
			c.Next()
			return
		}

		if time.Until(expirationTime.Time) < 15*time.Minute {
			refreshToken, err := c.Cookie("refresh_token")
			if err != nil || refreshToken == "" {
				c.Next()
				return
			}

			input := &cognito.InitiateAuthInput{
				AuthFlow: types.AuthFlowTypeRefreshToken,
				ClientId: aws.String(clientID),
				AuthParameters: map[string]string{
					"REFRESH_TOKEN": refreshToken,
				},
			}

			result, err := cognitoClient.InitiateAuth(context.TODO(), input)
			if err != nil {
				c.Next()
				return
			}

			domain := ""
			secure := false
			if os.Getenv("ENV") == "production" {
				secure = true
				domain = os.Getenv("COOKIE_DOMAIN")
			}

			sameSite := http.SameSiteLaxMode
			if os.Getenv("ENV") == "production" {
				sameSite = http.SameSiteStrictMode
			}

			c.SetSameSite(sameSite)
			c.SetCookie(
				"id_token",
				*result.AuthenticationResult.IdToken,
				int(result.AuthenticationResult.ExpiresIn),
				"/",
				domain,
				secure,
				true,
			)
		}

		c.Next()
	}
}
