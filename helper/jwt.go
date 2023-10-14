package helper

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateAccessToken(userId uint64) (string, error) {
	claims := jwt.MapClaims{
		"id":  userId,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(os.Getenv("ACCESS_TOKEN_KEY")))
}

func ValidateAccessToken(tokenString string, key string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Authentication validation failed")
		}

		return []byte(os.Getenv("ACCESS_TOKEN_KEY")), nil
	})

	if err != nil {
		switch err {
		case jwt.ErrTokenExpired:
			return nil, errors.New("Token expired. Please re-login")
		default:
			return nil, errors.New("Token invalid")
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("Token invalid")
	}

	return claims, nil
}
