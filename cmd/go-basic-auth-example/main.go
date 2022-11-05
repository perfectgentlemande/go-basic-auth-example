package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/perfectgentlemande/go-basic-auth-example/internal/logger"
	"github.com/perfectgentlemande/go-basic-auth-example/internal/service"
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

func (c *Controller) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	username, password, ok := r.BasicAuth()
	if !ok {
		WriteError(ctx, w, http.StatusUnauthorized, "No basic auth")
		return
	}

	token, err := c.srvc.Authorize(username, password)
	if err != nil {
		WriteError(ctx, w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
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

	prof, err := c.srvc.Verify(verifyRequest.Token)
	if err != nil {
		WriteError(ctx, w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	WriteSuccessful(ctx, w, prof)
}

type Controller struct {
	srvc *service.Service
}

func main() {
	cfg, err := readConfig("config.yaml")
	if err != nil {
		log.Fatal("Cannot read config: ", err)
	}

	srvc := service.NewService(cfg.Salt, cfg.Secret, cfg.MockedUsers)
	c := Controller{
		srvc: srvc,
	}

	r := chi.NewRouter()
	r.Post("/login", c.postLogin)
	r.Post("/verify", c.postVerify)

	http.ListenAndServe(cfg.Addr, r)
}
