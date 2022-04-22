package service

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"goweb/FHE_cloud/utils"
	"io/ioutil"
	"net/http"
	"os"
)

// IndexHandler 展示首页
func IndexHandler(c *gin.Context) {
	resultFiles, _ := ioutil.ReadDir("./files/resultFiles")
	resultFilesMap := make(map[int]string)
	for i, resultFile := range resultFiles {
		resultFilesMap[i] = resultFile.Name()
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"ResultFilesMap": resultFilesMap,
	})
}

// DownloadByName 下载文件
func DownloadByName(c *gin.Context) {
	filename, _ := c.Params.Get("filename")
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Transfer-Encoding", "binary")
	c.File("./files/resultFiles/" + filename)
}

// DeleteFileByName 删除文件
func DeleteFileByName(c *gin.Context) {
	var err error
	filename, _ := c.Params.Get("filename")
	err = os.Remove("./files/resultFiles/" + filename)
	if err != nil {
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/")
}

// Calculation 解析并计算表达式
func Calculation(c *gin.Context) {
	//获取文件并且保存到服务器
	calName, calSize := utils.SaveFile(c, "cal_file", "calFiles")
	pmName, pmSize := utils.SaveFile(c, "pm_file", "pmFiles")
	rlkName, rlkSize := utils.SaveFile(c, "rlk_file", "rlkFiles")

	//打开文件
	pmf, _ := os.Open("./files/pmFiles/" + pmName)
	defer func(pmf *os.File) {
		err := pmf.Close()
		if err != nil {

		}
	}(pmf)
	rkf, _ := os.Open("./files/rlkFiles/" + rlkName)
	defer func(pkf *os.File) {
		err := pkf.Close()
		if err != nil {

		}
	}(rkf)

	//读取文件内容
	pmb := make([]byte, pmSize)
	rkb := make([]byte, rlkSize)
	_, err := pmf.Read(pmb)
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err2 := rkf.Read(rkb)
	if err2 != nil {
		fmt.Println(err2.Error())
	}

	//反序列化
	var pm bfv.Parameters
	var rk *rlwe.RelinearizationKey
	err = json.Unmarshal(pmb, &pm)
	if err != nil {
		fmt.Println(err.Error())
	}
	err = json.Unmarshal(rkb, &rk)
	if err != nil {
		fmt.Println(err.Error())
	}
	//同态计算
	utils.FHECal(calName, calSize, pm, rk)
	c.Redirect(http.StatusMovedPermanently, "/")
}
