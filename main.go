package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func postLogin(w http.ResponseWriter, r *http.Request) {

}
func postVerify(w http.ResponseWriter, r *http.Request) {

}

func main() {
	r := chi.NewRouter()
	r.Post("/login", postLogin)
	r.Post("/verify", postVerify)

	http.ListenAndServe(":80", r)
}
