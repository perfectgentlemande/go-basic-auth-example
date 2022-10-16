package main

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/perfectgentlemande/go-basic-auth-example/internal/logger"
	"golang.org/x/crypto/pbkdf2"
)

type APIError struct {
	// Error message
	Message string `json:"message"`
}

func RespondWithJSON(w http.ResponseWriter, status int, payload interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(payload)
}
func WriteError(ctx context.Context, w http.ResponseWriter, status int, message string) {
	log := logger.GetLogger(ctx)

	err := RespondWithJSON(w, status, APIError{Message: message})
	if err != nil {
		log.WithError(err).Error("write response")
	}
}
func WriteSuccessful(ctx context.Context, w http.ResponseWriter, payload interface{}) {
	log := logger.GetLogger(ctx)

	err := RespondWithJSON(w, http.StatusOK, payload)
	if err != nil {
		log.WithError(err).Error("write response")
	}
}

func (c *Controller) authorize(username, password string) error {
	pass, ok := c.storedUsernamesWithPasswords[username]
	if !ok {
		return fmt.Errorf("no user with username: %s", username)
	}

	pwd := base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(password), []byte(c.salt), 4096, 32, sha1.New))
	if pass != pwd {
		return fmt.Errorf("wrong password for username: %s", username)
	}

	return nil
}

func (c *Controller) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	username, password, ok := r.BasicAuth()
	if !ok {
		WriteError(ctx, w, http.StatusUnauthorized, "No basic auth")
		return
	}

	if err := c.authorize(username, password); err != nil {
		WriteError(ctx, w, http.StatusUnauthorized, "Authorization failed")
		return
	}

	token, err := tokenBySecret(c.secret)(APIClaims{
		Profile: Profile{
			Username: username,
		},
		Expiration: time.Now().Add(time.Hour * 2),
	})
	if err != nil {
		WriteError(ctx, w, http.StatusUnauthorized, "cannot create token by secret")
		return
	}

	WriteSuccessful(ctx, w, VerifyRequest{Token: token})
}

type VerifyRequest struct {
	Token string `json:"token"`
}

func (c *Controller) postVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	verifyRequest := VerifyRequest{}
	err := json.NewDecoder(r.Body).Decode(&verifyRequest)
	if err != nil {
		WriteError(ctx, w, http.StatusBadRequest, "wrong request format")
		return
	}

	apiClaims := APIClaims{}
	t, err := parseWithSecret(c.secret)(verifyRequest.Token, &apiClaims)
	if err != nil {
		WriteError(ctx, w, http.StatusForbidden, "cannot parse token")
		return
	}

	if !t.Valid {
		WriteError(ctx, w, http.StatusForbidden, "invalid token")
		return
	}

	WriteSuccessful(ctx, w, apiClaims.Profile)
}

type Controller struct {
	storedUsernamesWithPasswords map[string]string
	salt                         string
	secret                       string
}

func main() {
	cfg, err := readConfig("config.yaml")
	if err != nil {
		log.Fatal("Cannot read config: ", err)
	}

	c := Controller{
		storedUsernamesWithPasswords: cfg.MockedUsers,
		salt:                         cfg.Salt,
		secret:                       cfg.Secret,
	}

	r := chi.NewRouter()
	r.Post("/login", c.postLogin)
	r.Post("/verify", c.postVerify)

	http.ListenAndServe(cfg.Addr, r)
}
