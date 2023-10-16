package request

import (
	"context"
	"encryption/helper"
	"fmt"
	"net/http"
	"strings"
)

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")

		next.ServeHTTP(w, r)
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		// cek prefix
		if !strings.HasPrefix(authorizationHeader, "Bearer ") {
			http.Error(w, "Token format invalid", http.StatusBadRequest)
			return
		}
		// split, cek token exists
		token := strings.Split(authorizationHeader, " ")[1]
		if token == "" {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		// verify token
		claims, err := helper.ValidateAccessToken(token)
		if err != nil {
			http.Error(w, "Token is required", http.StatusBadRequest)
			return
		}

		fmt.Println("dari claims")
		fmt.Println(claims["id"])
		ctx := context.WithValue(r.Context(), "user_id", claims["id"])

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
