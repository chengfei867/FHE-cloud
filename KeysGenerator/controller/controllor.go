package controller

import (
	"github.com/gin-gonic/gin"
	"goweb/KeysGenerator/service"
)

// KeyGenHandler 密钥生成模块
func KeyGenHandler(r *gin.Engine) {
	//首页
	r.GET("/", service.IndexHandler)
	//获取加密参数并且生成密钥
	r.POST("/keyGen", service.ParameterController)
	r.GET("/download/:filename", service.KeyFileDownload)
	r.GET("/delete/:filename", service.DeleteFileByName)
	r.POST("/encryption", service.ExpressParseToFile)
	r.POST("/decrypt", service.Decrypt)
}
