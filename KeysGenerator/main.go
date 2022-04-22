package main

import (
	"github.com/gin-gonic/gin"
	"goweb/KeysGenerator/controller"
)

func main() {
	r := gin.Default()
	//加载静态资源
	r.Static("/static", "static")
	r.LoadHTMLGlob("templates/*")
	//r.LoadHTMLFiles("templates/index.html")
	controller.KeyGenHandler(r)
	r.Run()
}
