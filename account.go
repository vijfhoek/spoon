package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/flosch/pongo2"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func validateEmail(email string) bool {
	matched, err := regexp.Match(".+@.+\\..+", []byte(email))
	return err == nil && matched
}
func validatePassword(password string) bool {
	return len(password) >= 8 && strings.ContainsAny(password, "0123456789")
}

func Register(w http.ResponseWriter, r *http.Request) {
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
	}

	context := pongo2.Context{}

	if r.Method == http.MethodPost {
		r.ParseForm()
		email := r.Form["email"][0]
		password := r.Form["password"][0]

		if !validateEmail(email) {
			context.Update(pongo2.Context{"error": "invalid_email"})
			fmt.Println("invalid email")
		} else if !validatePassword(password) {
			context.Update(pongo2.Context{"error": "invalid_password"})
			fmt.Println("invalid password")
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
			if err != nil {
				fmt.Println(err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			hashStr := base64.StdEncoding.EncodeToString(hash)

			// Insert the user into the database
			if err := DB.Create(&User{Email: email, Passhash: hashStr}).Error; err != nil {
				if err, ok := err.(*pq.Error); ok && err.Code.Name() == "unique_violation" {
					context.Update(pongo2.Context{"error": "duplicate_email"})
					fmt.Println("duplicate email")
				} else {
					fmt.Println(err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}
		}

	}

	if err := TplRegister.ExecuteWriter(context, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func checkCreds(w http.ResponseWriter, r *http.Request) (user User, err error) {
	r.ParseForm()
	email := r.Form["email"][0]
	password := r.Form["password"][0]

	if err = DB.First(&user, "email=$1", email).Error; err != nil {
		if err.Error() == "record not found" {
			fmt.Println("invalid credentials")
			err = nil
		} else {
			fmt.Println(err)
		}

		user.ID = 0
		return
	}

	// Decode the hash
	hash, err := base64.StdEncoding.DecodeString(user.Passhash)
	if err != nil {
		fmt.Println(err)
		user.ID = 0
		return
	}

	// Check the password
	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		fmt.Println("invalid credentials")
		return
	}

	return
}

func Login(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If the user already is logged in, redirect them to /
	fmt.Println(session.Values["userID"])
	if userID, ok := session.Values["userID"].(uint); ok && userID > 0 {
		session.Save(r, w)
		http.Redirect(w, r, "/app", 301)
		return
	}

	if r.Method == http.MethodPost {
		// Try to login
		user, err := checkCreds(w, r)
		if err != nil {
			// If an error occured, throw an error 500
			fmt.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		} else if user.ID > 0 {
			// If logged in successfully, set the session and redirect the user to /
			print("User ", user.Email, " logged in successfully")
			session.Values["userID"] = user.ID
			session.Save(r, w)
			http.Redirect(w, r, "/app", 301)
		} else {
			// If the credentials were invalid, tell the user
			session.Save(r, w)
			ctx := pongo2.Context{"error": "invalid_credentials", "userID": user.ID}
			if err := TplLogin.ExecuteWriter(ctx, w); err != nil {
				fmt.Println(err.Error())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	} else {
		session.Save(r, w)
		if err := TplLogin.ExecuteWriter(nil, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
