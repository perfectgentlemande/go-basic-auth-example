package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"

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
		return fmt.Errorf("No user with username: %s", username)
	}

	pwd := string(pbkdf2.Key([]byte(password), []byte(c.salt), 4096, 32, sha1.New))
	if pass != pwd {
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
	salt                         string
}

func main() {
	c := Controller{
		storedUsernamesWithPasswords: map[string]string{
			// tst_pwd_01
			"tst_usr_01": string([]byte{211, 157, 140, 249, 4, 171, 115, 195, 58, 50, 239, 253, 122, 187, 63, 33, 118, 240, 190, 57, 208, 131, 251, 22, 150, 166, 203, 200, 27, 129, 107, 41}),
			// tst_pwd_02
			"tst_usr_02": string([]byte{204, 238, 205, 169, 0, 192, 149, 151, 193, 101, 104, 48, 194, 211, 21, 196, 113, 80, 198, 118, 15, 0, 145, 142, 136, 155, 113, 236, 204, 13, 202, 68}),
		},
		salt: "RKt1Q@6Es@vdrh.iyg.4OMuuiKwf)ui_rJ9-4*SW.(yY47(TjVWrVuf1Blw(OFdq",
	}

	r := chi.NewRouter()
	r.Post("/login", c.postLogin)
	r.Post("/verify", c.postVerify)

	http.ListenAndServe(":80", r)
}
