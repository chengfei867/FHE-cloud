package service

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"goweb/KeysGenerator/utils"
	"io/ioutil"
	"net/http"
	"os"
	"path"
)

var ParametersMap = map[string]bfv.ParametersLiteral{
	"PN12QP109":   bfv.PN12QP109,
	"PN13QP218":   bfv.PN13QP218,
	"PN14QP438":   bfv.PN14QP438,
	"PN12QP101pq": bfv.PN12QP101pq,
	"PN13QP202pq": bfv.PN13QP202pq,
	"PN14QP411pq": bfv.PN14QP411pq,
}

// IndexHandler 首页处理函数
func IndexHandler(c *gin.Context) {
	keyFiles, err := ioutil.ReadDir("./keys")
	cipherFiles, _ := ioutil.ReadDir("./cipherFiles")
	if err != nil {
		c.JSON(http.StatusOK, err)
	}
	keyFilesMap := make(map[int]string)
	for i, keyFile := range keyFiles {
		keyFilesMap[i] = keyFile.Name()
	}
	cipherFilesMap := make(map[int]string)
	for i, cipherFile := range cipherFiles {
		cipherFilesMap[i] = cipherFile.Name()
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"ParametersMap":  ParametersMap,
		"KeyFilesMap":    keyFilesMap,
		"CipherFilesMap": cipherFilesMap,
	})
}

// ParameterController 处理加密参数中间件
func ParameterController(c *gin.Context) {
	//获取加密参数
	parameter := c.PostForm("parameter")
	paramDef := ParametersMap[parameter]
	//根据加密参数生成密钥
	parameters := utils.ParamsSelect(paramDef)
	sk, pk, rk := utils.KeyGenerator(parameters)
	//格式化密钥,便于写入文件
	skp, _ := json.Marshal(sk)
	pkp, _ := json.Marshal(pk)
	rkp, _ := json.Marshal(rk)
	pmp, _ := json.Marshal(parameters)
	filename := c.PostForm("filename")
	//私钥写入文件
	utils.WriteIntoFile("sk_"+filename, skp)
	//公钥写入文件
	utils.WriteIntoFile("pk_"+filename, pkp)
	//重线性化密钥写入文件
	utils.WriteIntoFile("rk_"+filename, rkp)
	//加密参数写入文件
	utils.WriteIntoFile("pm_"+filename, pmp)
	c.Redirect(http.StatusMovedPermanently, "/")
}

// KeyFileDownload 密钥文件下载
func KeyFileDownload(c *gin.Context) {
	filename, _ := c.Params.Get("filename")
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Transfer-Encoding", "binary")
	if filename[0:3] == "cp_" {
		c.File("./cipherFiles/" + filename)
	} else {
		c.File("./keys/" + filename)
	}
}

// DeleteFileByName 删除指定文件
func DeleteFileByName(c *gin.Context) {
	var err error
	filename, _ := c.Params.Get("filename")
	if filename[:3] == "cp_" {
		err = os.Remove("./cipherFiles/" + filename)
	} else {
		err = os.Remove("./keys/" + filename)
	}
	if err != nil {
		return
	}
	c.Redirect(http.StatusMovedPermanently, "/")
}

// ExpressParseToFile 加密表达式并且保存为本地文件
func ExpressParseToFile(c *gin.Context) {
	//获取表达式
	express := c.PostForm("express")
	//获取文件名
	pmFile, _ := c.FormFile("pm_file")
	pkFile, _ := c.FormFile("pk_file")
	//打开文件
	pmf, _ := os.Open("./keys/" + pmFile.Filename)
	defer func(pmf *os.File) {
		err := pmf.Close()
		if err != nil {

		}
	}(pmf)
	pkf, _ := os.Open("./keys/" + pkFile.Filename)
	defer func(pkf *os.File) {
		err := pkf.Close()
		if err != nil {

		}
	}(pkf)

	//读取文件内容
	pmb := make([]byte, pmFile.Size)
	pkb := make([]byte, pkFile.Size)
	_, err := pmf.Read(pmb)
	if err != nil {
		return
	}
	_, err2 := pkf.Read(pkb)
	if err2 != nil {
		return
	}

	//反序列化
	var pm bfv.Parameters
	var pk *rlwe.PublicKey
	err = json.Unmarshal(pmb, &pm)
	if err != nil {
		fmt.Println(err.Error())
	}
	err = json.Unmarshal(pkb, &pk)
	if err != nil {
		fmt.Println(err.Error())
	}

	utils.ExpressEncryption(express, pm, pk)
	c.Redirect(http.StatusMovedPermanently, "/")
}

// Decrypt 解密得到最终计算结果
func Decrypt(c *gin.Context) {
	reFile, _ := c.FormFile("re_file")
	skFile, _ := c.FormFile("sk_file")
	pmFile, _ := c.FormFile("pmt_file")

	//将reFile保存起来
	dst := path.Join("./results/", reFile.Filename)
	err := c.SaveUploadedFile(reFile, dst)
	if err != nil {
		return
	}

	//读取reFile和skFile
	pmf, _ := os.Open("./keys/" + pmFile.Filename)
	defer func(pkf *os.File) {
		err := pkf.Close()
		if err != nil {

		}
	}(pmf)
	skf, _ := os.Open("./keys/" + skFile.Filename)
	defer func(pmf *os.File) {
		err := pmf.Close()
		if err != nil {

		}
	}(skf)
	ref, _ := os.Open("./results/" + reFile.Filename)
	defer func(pkf *os.File) {
		err := pkf.Close()
		if err != nil {

		}
	}(ref)

	//读取文件内容
	pmb := make([]byte, pmFile.Size)
	skb := make([]byte, skFile.Size)
	reb := make([]byte, reFile.Size)
	_, err = pmf.Read(pmb)
	if err != nil {
		return
	}
	_, err = skf.Read(skb)
	if err != nil {
		return
	}
	_, err = ref.Read(reb)
	if err != nil {
		return
	}

	//反序列化
	var pm bfv.Parameters
	var sk *rlwe.SecretKey
	var re *bfv.Ciphertext
	err = json.Unmarshal(pmb, &pm)
	err = json.Unmarshal(skb, &sk)
	err = json.Unmarshal(reb, &re)
	if err != nil {
		fmt.Println(err.Error())
	}
	result := utils.Decryption(re, pm, sk)
	c.HTML(http.StatusOK, "result.html", result)
}
