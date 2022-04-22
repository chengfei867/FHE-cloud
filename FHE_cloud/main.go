package main

import (
	"github.com/gin-gonic/gin"
	"goweb/FHE_cloud/controller"
)

func main() {
	r := gin.Default()
	//加载静态资源
	r.Static("/static", "static")
	r.LoadHTMLFiles("templates/index.html")
	controller.CloudCalHandler(r)
	r.Run(":9090")
}
