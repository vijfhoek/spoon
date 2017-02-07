package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var (
	Store *sessions.CookieStore
	DB    *gorm.DB
	CFG   Configuration
)

func main() {
	var err error
	if CFG, err = readConfig(); err != nil {
		fmt.Println("Couldn't open config:", err)
		return
	}

	options := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
		CFG.DbUser, CFG.DbPassword, CFG.DbName)
	if DB, err = gorm.Open("postgres", options); err != nil {
		fmt.Println(err)
		return
	}
	DB.AutoMigrate(&User{}, &Room{})

	Store = sessions.NewCookieStore([]byte(CFG.SecretKey))

	http.HandleFunc("/", Index)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/app", App)
	http.Handle("/static/", http.FileServer(http.Dir('.')))
	http.ListenAndServe(":8080", context.ClearHandler(http.DefaultServeMux))
}
