package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/flosch/pongo2"
	"github.com/gorilla/sessions"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func internalServerError(w http.ResponseWriter, err error) {
	fmt.Println(err.Error())
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func methodNotAllowed(w http.ResponseWriter) {
}

var (
	TplIndex    = pongo2.Must(pongo2.FromFile("templates/index.html"))
	TplRegister = pongo2.Must(pongo2.FromFile("templates/register.html"))
	TplLogin    = pongo2.Must(pongo2.FromFile("templates/login.html"))
	TplApp      = pongo2.Must(pongo2.FromFile("templates/app.html"))
)

func Index(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		internalServerError(w, err)
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
		internalServerError(w, err)
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
				internalServerError(w, err)
				return
			}
			hashStr := base64.StdEncoding.EncodeToString(hash)

			// Insert the user into the database
			if err := DB.Create(&User{Email: email, Passhash: hashStr}).Error; err != nil {
				if err, ok := err.(*pq.Error); ok && err.Code.Name() == "unique_violation" {
					context.Update(pongo2.Context{"error": "duplicate_email"})
					fmt.Println("duplicate email")
				} else {
					internalServerError(w, err)
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
		internalServerError(w, err)
		return
	}

	// If the user already is logged in, redirect them to /app
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
			// Throw an ISE if something went wrong
			internalServerError(w, err)
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
				internalServerError(w, err)
			}
		}
	} else {
		session.Save(r, w)
		if err := TplLogin.ExecuteWriter(nil, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func App(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		internalServerError(w, err)
		return
	}

	// If the user isn't logged in, redirect them to the login page
	user := getUser(w, session)
	if user.ID == 0 {
		http.Redirect(w, r, "/login", 301)
		return
	}

	if r.Method == "POST" {
		r.ParseForm()
		action := r.Form["action"][0]
		name := r.Form["name"][0]

		// Get the user's roommates
		var roommates []User
		if err := DB.Where("id <> ?", user.ID).Find(&roommates).Error; err != nil {
			internalServerError(w, err)
			return
		}

		if action == "addItem" {
			DB.Create(&GroceryItem{Name: name, RoomID: user.RoomID})
		}

		http.Redirect(w, r, "/app", 301)
		return
	}

	// Retrieve the user's room's grocery list
	var (
		room         Room
		groceryItems []GroceryItem
		dueItems     []GroceryItem
		dueRxItems   []GroceryItem
	)

	// Build the user- and room objects
	DB.Preload("Users").Model(&user).Related(&room)
	DB.Preload("User").Model(&user).Related(&dueItems, "DueItems")
	DB.Preload("DueUsers").Model(&user).Related(&dueRxItems, "DueRxItems")
	DB.Model(&room).Related(&groceryItems)

	ctx := pongo2.Context{"groceryItems": groceryItems, "dueItems": dueItems, "dueRxItems": dueRxItems, "room": room}
	if err := TplApp.ExecuteWriter(ctx, w); err != nil {
		internalServerError(w, err)
	}
}

func getUser(w http.ResponseWriter, session *sessions.Session) (user User) {
	// If the user isn't logged in, throw a 401
	userID, ok := session.Values["userID"].(uint)
	if !ok || userID == 0 {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
		user.ID = 0
	} else if DB.First(&user, userID).RecordNotFound() {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
		user.ID = 0
	}

	return
}

func ApiCheckItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "<h1>Method Not Allowed</h1>", http.StatusMethodNotAllowed)
		return
	}

	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		internalServerError(w, err)
		return
	}

	user := getUser(w, session)
	if user.ID == 0 {
		internalServerError(w, err)
		return
	}

	// Get the user's roommates
	var roommates []User
	if err := DB.Where("id <> ?", user.ID).Find(&roommates).Error; err != nil {
		internalServerError(w, err)
		return
	}

	// Decode the body
	r.ParseForm()
	itemID, err1 := strconv.Atoi(r.Form["itemID"][0])
	cost, err2 := strconv.Atoi(r.Form["cost"][0])
	if err1 != nil || err2 != nil || cost < 0 {
		http.Error(w, "<h1>Bad request</h1>", http.StatusBadRequest)
		return
	}

	// Add the item to the database
	var item GroceryItem
	if err := DB.First(&item, itemID).Error; err != nil {
		http.Error(w, "<h1>item_id "+string(itemID)+" not found.</h1>", http.StatusNotFound)
		return
	}
	if item.RoomID != user.RoomID {
		http.Error(w, "<h1>Forbidden</h1>This is not your room.", http.StatusForbidden)
		return
	}

	item.Cost = cost
	item.Split = cost / (len(roommates) + 1)
	item.UserID = user.ID
	if err := DB.Save(&item).Error; err != nil {
		internalServerError(w, err)
		return
	}

	// Split the item over other roommates
	for _, roommate := range roommates {
		DB.Create(&DueUserItem{GroceryItemID: item.ID, UserID: roommate.ID})
		println(roommate.Name)
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		internalServerError(w, err)
	}
}
