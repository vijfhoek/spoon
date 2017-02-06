package main

import (
	"github.com/flosch/pongo2"
	"net/http"
)

// Pre-compile the templates
var tplIndex = pongo2.Must(pongo2.FromFile("templates/index.html"))
var tplRegister = pongo2.Must(pongo2.FromFile("templates/register.html"))

func index(w http.ResponseWriter, r *http.Request) {
	err := tplIndex.ExecuteWriter(pongo2.Context{"query": r.FormValue("query")}, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	err := tplRegister.ExecuteWriter(pongo2.Context{"query": r.FormValue("query")}, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.Handle("/static/", http.FileServer(http.Dir('.')))
	http.ListenAndServe(":8080", nil)
}
