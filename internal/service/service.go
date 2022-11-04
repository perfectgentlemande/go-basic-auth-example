package service

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/xdg-go/pbkdf2"
)

type Service struct {
	secret                       string
	storedUsernamesWithPasswords map[string]string
}

func NewService(secret string, usernamesWithPasswords map[string]string) *Service {
	return &Service{
		secret:                       secret,
		storedUsernamesWithPasswords: usernamesWithPasswords,
	}
}

func (s *Service) checkCredentials(username, password string) error {
	pass, ok := s.storedUsernamesWithPasswords[username]
	if !ok {
		return fmt.Errorf("no user with username: %s", username)
	}

	pwd := base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(password), []byte(c.salt), 4096, 32, sha1.New))
	if pass != pwd {
		return fmt.Errorf("wrong password for username: %s", username)
	}

	return nil
}

func (s *Service) authorize(username, password string) (string, error) {
	if err := s.checkCredentials(username, password); err != nil {
		return "", fmt.Errorf("invalid credentials: %w", err)
	}

	token, err := tokenBySecret(s.secret)(ServiceClaims{
		Profile: Profile{
			Username: username,
		},
		Expiration: time.Now().Add(time.Hour * 2),
	})
	if err != nil {
		return "", fmt.Errorf("cannot create token by secret: %w", err)
	}

	return token, nil
}

func (s *Service) verify(token string) (Profile, error) {
	serviceClaims := ServiceClaims{}
	t, err := parseWithSecret(s.secret)(token, &serviceClaims)
	if err != nil {
		return Profile{}, fmt.Errorf("cannot parse token: %s: %w", token, err)
	}

	if !t.Valid {
		return Profile{}, fmt.Errorf("invalid token: %s", token)
	}

	return serviceClaims.Profile, nil
}
