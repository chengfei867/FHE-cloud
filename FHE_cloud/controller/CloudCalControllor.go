package controller

import (
	"github.com/gin-gonic/gin"
	"goweb/FHE_cloud/service"
)

// CloudCalHandler 云上的密文计算服务
func CloudCalHandler(r *gin.Engine) {
	r.GET("/", service.IndexHandler)
	r.POST("/calculation", service.Calculation)
	r.GET("/download/:filename", service.DownloadByName)
	r.GET("/delete/:filename", service.DeleteFileByName)
}
