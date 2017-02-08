package main

import "github.com/jinzhu/gorm"

// Room is an ORM model of the rooms table. Represents a student room.
type Room struct {
	gorm.Model
	Name         string        `gorm:"not null"`
	GroceryItems []GroceryItem `gorm:"ForeignKey:RoomID"`
	Users        []User        `gorm:"ForeignKey:RoomID"`
}

// User is an ORM model of the users table. Represents a student.
type User struct {
	gorm.Model
	Email    string `gorm:"not null;unique"`
	Passhash string `gorm:"not null"`
	Name     string

	// The Room the user belongs to
	RoomID uint
	Room   Room `gorm:"ForeignKey:RoomID"`

	// The GroceryItems the user still has to pay for
	DueItems []GroceryItem `gorm:"many2many:due_user_items"`

	// The GroceryItems the user still has to be paid for
	DueRxItems []GroceryItem `gorm:"ForeignKey:UserID"`
}

// GroceryItem is an ORM model of the grocery_items table. Represents an item on the grocery list.
type GroceryItem struct {
	gorm.Model
	Name   string `gorm:"not null"`
	RoomID uint
	Cost   int

	// The cost for each roommate
	Split int

	// The User that has bought this item
	UserID uint
	User   User `gorm:"ForeignKey:UserID"`

	// The Users that still have to pay for this item
	DueUsers     []User        `gorm:"many2many:due_user_items"`
	DueUserItems []DueUserItem `gorm:"ForeignKey:GroceryItemID"`
}

// DueUserItem is an ORM model of the due_user_items table. Maps users to items they still have to pay for.
type DueUserItem struct {
	gorm.Model

	GroceryItemID uint
	GroceryItem   GroceryItem `gorm:"ForeignKey:GroceryItemID"`

	UserID uint
}
