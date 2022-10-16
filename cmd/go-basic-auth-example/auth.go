package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type Profile struct {
	Username string `json:"username"`
	Fullname string `json:"fullname"`
}

type APIClaims struct {
	Profile
	Expiration time.Time `json:"exp"`
}

func (p APIClaims) Valid() error {
	if p.Expiration.Before(time.Now()) {
		return errors.New("token has expired")
	}
	return nil
}

func tokenBySecret(secret string) func(jwt.Claims) (string, error) {
	return func(c jwt.Claims) (string, error) {
		t := jwt.New(jwt.SigningMethodHS512)
		t.Claims = c
		return t.SignedString([]byte(secret))
	}
}

func parseWithSecret(secret string) func(string, jwt.Claims) (*jwt.Token, error) {
	return func(token string, cl jwt.Claims) (*jwt.Token, error) {
		return jwt.ParseWithClaims(token, cl, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if token.Method != jwt.SigningMethodHS512 {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})
	}
}
