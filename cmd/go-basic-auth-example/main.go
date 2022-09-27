package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/perfectgentlemande/go-basic-auth-example/internal/logger"
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
		return fmt.Errorf("No user with username: %s", username)
	}

	if pass != password {
		return fmt.Errorf("Wrong password for username: %s", username)
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
}
func (c *Controller) postVerify(w http.ResponseWriter, r *http.Request) {

}

type Controller struct {
	storedUsernamesWithPasswords map[string]string
}

func main() {
	c := Controller{
		storedUsernamesWithPasswords: map[string]string{
			"tst_usr_01": "tst_pwd_01",
			"tst_usr_02": "tst_pwd_02",
		},
	}

	r := chi.NewRouter()
	r.Post("/login", c.postLogin)
	r.Post("/verify", c.postVerify)

	http.ListenAndServe(":80", r)
}
