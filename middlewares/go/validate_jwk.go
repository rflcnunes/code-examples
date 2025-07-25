package middleware

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
)

const issuerURL = "https://your.auth.url.com.br" // change your provider url

var (
	jwksURI      = issuerURL + "/protocol/openid-connect/certs" // change to your url
	httpClient   = &http.Client{Timeout: 10 * time.Second}
	jwksCache    *JWKSResponse
	jwksCacheExp time.Time
	cacheMu      sync.RWMutex
)

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			setCORSHeaders(c)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("kid not found in token header")
			}

			jwks, err := getJWKS()
			if err != nil {
				return nil, fmt.Errorf("failed to get JWKS: %w", err)
			}

			for _, key := range jwks.Keys {
				if key.Kid == kid {
					return jwkToRSAKey(key)
				}
			}
			return nil, fmt.Errorf("key not found for kid %s", kid)
		})

		if err != nil {
			log.Error().Err(err).Msg("JWT validation failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not valid"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func setCORSHeaders(c *gin.Context) {
	for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
		c.Header(h, "*")
	}
}

func getJWKS() (*JWKSResponse, error) {
	cacheMu.RLock()
	if jwksCache != nil && time.Now().Before(jwksCacheExp) {
		defer cacheMu.RUnlock()
		return jwksCache, nil
	}
	cacheMu.RUnlock()

	resp, err := httpClient.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	cacheMu.Lock()
	jwksCache = &jwks
	jwksCacheExp = time.Now().Add(1 * time.Hour)
	cacheMu.Unlock()

	return &jwks, nil
}

func jwkToRSAKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}
