package main

import "github.com/jinzhu/gorm"

// Room is an ORM model of the rooms table. Represents a student room
type Room struct {
	gorm.Model
	Name   string `gorm:"not null"`
	UserID uint
}

// User is an ORM model of the users table. Represents a student
type User struct {
	gorm.Model
	Email    string `gorm:"not null;unique"`
	Passhash string `gorm:"not null"`
	Room     Room   `gorm:"ForeignKey:UserID"`
}
