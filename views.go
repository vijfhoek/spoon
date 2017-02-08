package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/flosch/pongo2"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func internalServerError(w http.ResponseWriter, err error) {
	fmt.Println(err.Error())
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		http.Redirect(w, r, "/app", 302)
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
		http.Redirect(w, r, "/app", 302)
	}

	context := pongo2.Context{}

	if r.Method == http.MethodPost {
		// Retrieve the form fields
		r.ParseForm()
		email := r.Form["email"][0]
		password := r.Form["password"][0]

		if !validateEmail(email) {
			// Make sure the e-mail address is of format user@hostname.tld
			context.Update(pongo2.Context{"error": "invalid_email"})
			fmt.Println("invalid email")
		} else if !validatePassword(password) {
			// Make sure the password conforms to the requirements
			// (minimum of 8 characters, at least 1 digit)
			context.Update(pongo2.Context{"error": "invalid_password"})
			fmt.Println("invalid password")
		} else {
			// Generate the password hash
			hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
			if err != nil {
				internalServerError(w, err)
				return
			}
			hashStr := base64.StdEncoding.EncodeToString(hash)

			// Insert the user into the database
			if err := DB.Create(&User{Email: email, Passhash: hashStr}).Error; err != nil {
				if errPq, ok := err.(*pq.Error); ok && errPq.Code.Name() == "unique_violation" {
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

	// Check if the e-mail address has been registered
	if DB.First(&user, "email=$1", email).RecordNotFound() {
		fmt.Println("invalid credentials")

		err = nil
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
		http.Redirect(w, r, "/app", 302)
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
			http.Redirect(w, r, "/app", 302)
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

func Logoff(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	session, err := Store.Get(r, "spoon-session")
	if err != nil {
		internalServerError(w, err)
		return
	}

	if _, ok := session.Values["userID"]; ok {
		delete(session.Values, "userID")
	}

	session.Save(r, w)
	http.Redirect(w, r, "/", 302)
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
		http.Redirect(w, r, "/login", 302)
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

		http.Redirect(w, r, "/app", 302)
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
	DB.Preload("User").Model(&user).Where("due_user_items.deleted_at IS NULL").Related(&dueItems, "DueItems")
	DB.Preload("DueUsers").Model(&user).Related(&dueRxItems, "DueRxItems")
	DB.Model(&room).Related(&groceryItems)

	ctx := pongo2.Context{"groceryItems": groceryItems, "dueItems": dueItems, "dueRxItems": dueRxItems, "user": user, "room": room}
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

func getSessionAndUser(w http.ResponseWriter, r *http.Request) (session *sessions.Session, user User, err error) {
	// Get the user's session
	session, err = Store.Get(r, "spoon-session")
	if err != nil {
		internalServerError(w, err)
		return
	}

	user = getUser(w, session)
	return
}

func ApiPostItemCost(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	_, user, err := getSessionAndUser(w, r)
	if err != nil {
		internalServerError(w, err)
		return
	} else if user.ID == 0 {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
	}

	// Get the user's roommates
	var roommates []User
	if err := DB.Where("id <> ?", user.ID).Find(&roommates).Error; err != nil {
		internalServerError(w, err)
		return
	}

	// Decode the body
	r.ParseForm()
	cost, err := strconv.Atoi(r.Form["cost"][0])
	itemID := mux.Vars(r)["id"]
	if err != nil || cost < 0 {
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
		http.Error(w, "<h1>Forbidden</h1>\nThis is not your room.", http.StatusForbidden)
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

func ApiDeleteItem(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	_, user, err := getSessionAndUser(w, r)
	if err != nil {
		internalServerError(w, err)
		return
	} else if user.ID == 0 {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
	}

	itemID, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "<h1>Bad Request</h1>", http.StatusBadRequest)
		return
	}
	DB.Delete(GroceryItem{}, "id=?", itemID)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		internalServerError(w, err)
	}
}

func ApiPutItem(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	_, user, err := getSessionAndUser(w, r)
	if err != nil {
		internalServerError(w, err)
		return
	} else if user.ID == 0 {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
	}

	r.ParseForm()
	name := r.Form["name"][0]

	if err := DB.Create(&GroceryItem{Name: name, RoomID: user.RoomID}).Error; err != nil {
		internalServerError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		internalServerError(w, err)
	}
}

func ApiPutItemPaid(w http.ResponseWriter, r *http.Request) {
	// Get the user's session
	_, user, err := getSessionAndUser(w, r)
	if err != nil {
		internalServerError(w, err)
		return
	} else if user.ID == 0 {
		http.Error(w, "<h1>Unauthorized</h1>", http.StatusUnauthorized)
		return
	}

	r.ParseForm()
	itemID, err := strconv.Atoi(mux.Vars(r)["id"])
	if err != nil {
		http.Error(w, "<h1>Bad Request</h1>", http.StatusBadRequest)
		return
	}

	if err := DB.Delete(DueUserItem{}, "user_id=? AND grocery_item_id=?", user.ID, itemID).Error; err != nil {
		internalServerError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		internalServerError(w, err)
	}
}
