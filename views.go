package main

import "github.com/flosch/pongo2"

var (
	TplIndex    = pongo2.Must(pongo2.FromFile("templates/index.html"))
	TplRegister = pongo2.Must(pongo2.FromFile("templates/register.html"))
	TplLogin    = pongo2.Must(pongo2.FromFile("templates/login.html"))
)
