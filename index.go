package main

import (
	"fmt"
	"net/http"

	"github.com/flosch/pongo2"
)

func Index(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If the user already is logged in, redirect them to /
	if userID, ok := session.Values["userID"].(uint); ok && userID > 0 {
		session.Save(r, w)
		http.Redirect(w, r, "/app", 301)
		return
	}

	if err := TplIndex.ExecuteWriter(pongo2.Context{"query": r.FormValue("query")}, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
