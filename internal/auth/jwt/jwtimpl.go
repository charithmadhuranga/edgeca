/*******************************************************************************
 * Copyright 2021 EdgeSec Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 *******************************************************************************/

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	golangjwt "github.com/golang-jwt/jwt"
	"github.com/prometheus/common/log"
)

var jwtKey *rsa.PrivateKey

var jwtContext = &contextKey{"userid"}

type contextKey struct {
	name string
}

func GenerateToken() (string, error) {
	var err error

	if jwtKey == nil {
		keyLength := 1024
		jwtKey, err = rsa.GenerateKey(rand.Reader, keyLength)
	}

	if err != nil {
		return "", err
	}

	token := golangjwt.NewWithClaims(golangjwt.SigningMethodRS256, golangjwt.MapClaims{
		"iss": "EdgeCA",
		"sub": "user",
		"exp": time.Now().AddDate(0, 1, 0).UTC().Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(jwtKey)

	return tokenString, err
}

func ParseToken(tokenString string) (string, error) {

	token, err := golangjwt.Parse(tokenString, func(token *golangjwt.Token) (interface{}, error) {
		return &jwtKey.PublicKey, nil
	})

	if err != nil {

		return "", err
	}

	claims, ok := token.Claims.(golangjwt.MapClaims)

	if claims == nil {
		log.Errorf("claims == nil")
	}

	if !ok {
		log.Errorf("!ok")
	}

	if ok && token.Valid {
		username := claims["sub"].(string)
		return username, nil
	} else {
		return "", err
	}
}

func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")

			// Allow unauthenticated users in
			if header == "" {
				next.ServeHTTP(w, r)
				return
			}

			tokenStr := header
			username, err := ParseToken(tokenStr)
			var userid string
			if err != nil {
				log.Infof("GraphQL JWT token error: %v", err)
			} else {
				userid, err = getUserID(username)
				if err != nil {
					log.Infof("GraphQL JWT token error: invalid user")
				}
			}
			c := context.WithValue(r.Context(), jwtContext, &userid)
			r = r.WithContext(c)
			next.ServeHTTP(w, r)
		})
	}
}

func getUserID(username string) (id string, err error) {
	if username == "user" {
		return "1", nil
	} else {
		return "", fmt.Errorf("user %s unknown", username)
	}
}

func UserIDFromContext(ctx context.Context) string {
	userID, _ := ctx.Value(jwtContext).(*string)
	if userID == nil {
		return ""
	} else {
		return *userID

	}
}
