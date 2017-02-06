package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/flosch/pongo2"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Pre-compile the templates
var (
	tplIndex    = pongo2.Must(pongo2.FromFile("templates/index.html"))
	tplRegister = pongo2.Must(pongo2.FromFile("templates/register.html"))
	tplLogin    = pongo2.Must(pongo2.FromFile("templates/login.html"))
)

// Connect to the database
var db *sql.DB

func index(w http.ResponseWriter, r *http.Request) {
	err := tplIndex.ExecuteWriter(pongo2.Context{"query": r.FormValue("query")}, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func checkEmail(email string) bool {
	matched, err := regexp.Match(".+@.+\\..+", []byte(email))
	return err == nil && matched
}
func checkPassword(password string) bool {
	return len(password) >= 8 && strings.ContainsAny(password, "0123456789")
}

func register(w http.ResponseWriter, r *http.Request) {
	context := pongo2.Context{}

	if r.Method == http.MethodPost {
		r.ParseForm()

		email := r.Form["email"][0]
		password := r.Form["password"][0]

		if !checkEmail(email) {
			context.Update(pongo2.Context{"error": "invalid_email"})
			fmt.Println("invalid email")
		} else if !checkPassword(password) {
			context.Update(pongo2.Context{"error": "invalid_password"})
			fmt.Println("invalid password")
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
			if err != nil {
				fmt.Println(err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			hash_str := base64.StdEncoding.EncodeToString(hash)

			// Insert the user into the database
			_, err = db.Exec("INSERT INTO users(email, passhash) VALUES($1, $2)", email, hash_str)
			pq_err, ok := err.(*pq.Error)
			if ok {
				if pq_err.Code.Name() == "unique_violation" {
					context.Update(pongo2.Context{"error": "used_email"})
					fmt.Println("used email")
				} else {
					fmt.Println(pq_err.Code.Name())
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			} else {
				fmt.Println(err)
			}

		}

	}

	err := tplRegister.ExecuteWriter(context, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {

	}

	err := tplLogin.ExecuteWriter(pongo2.Context{}, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type Configuration struct {
	DbUser     string
	DbPassword string
	DbName     string
}

var cfg = Configuration{}

func readConfig() error {
	file, err := os.Open("config.json")
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(file)
	return decoder.Decode(&cfg)
}

func main() {
	err := readConfig()
	if err != nil {
		fmt.Println("Couldn't open config:", err)
		return
	}

	conn, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", cfg.DbUser, cfg.DbPassword, cfg.DbName))
	if err != nil {
		fmt.Println(err)
		return
	}
	db = conn

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.Handle("/static/", http.FileServer(http.Dir('.')))
	http.ListenAndServe(":8080", nil)
}
