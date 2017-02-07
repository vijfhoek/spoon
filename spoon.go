package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// Pre-compile the templates
var (
	Store *sessions.CookieStore
	DB    *gorm.DB
)

type configuration struct {
	DbUser     string
	DbPassword string
	DbName     string

	SecretKey string
}

var cfg = configuration{}

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

	DB, err = gorm.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", cfg.DbUser, cfg.DbPassword, cfg.DbName))
	if err != nil {
		fmt.Println(err)
		return
	}
	DB.AutoMigrate(&User{}, &Room{})

	Store = sessions.NewCookieStore([]byte(cfg.SecretKey))

	http.HandleFunc("/", Index)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.Handle("/static/", http.FileServer(http.Dir('.')))
	http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
}
