package utils

import (
	"encoding/json"
	"fmt"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"os"
	"strconv"
	"time"
)

//var T = uint64(0x3ee0001)

// Express 表达式结构体
type Express struct {
	//存放操作符
	Operators []string
	//存放密文数字
	Nums map[int]*bfv.Ciphertext
}

// ParamsSelect 选择加密参数
func ParamsSelect(paramDef bfv.ParametersLiteral) bfv.Parameters {
	//paramDef.T = T
	params, err := bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}
	return params
}

// KeyGenerator 密钥生成(sk:私钥 pk:公钥 rlk:重线性化参数)
func KeyGenerator(params bfv.Parameters) (Sk *rlwe.SecretKey, Pk *rlwe.PublicKey, rlk *rlwe.RelinearizationKey) {
	kgen := bfv.NewKeyGenerator(params)
	Sk, Pk = kgen.GenKeyPair()
	rlk = kgen.GenRelinearizationKey(Sk, 2)
	return Sk, Pk, rlk
}

// WriteIntoFile 将密钥写入文件
func WriteIntoFile(filename string, kp []byte) {
	timeStamp := strconv.Itoa(int(time.Now().Unix()))
	keyFile, err := os.Create("./keys/" + filename + timeStamp + ".txt")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer func(keyFile *os.File) {
		err := keyFile.Close()
		if err != nil {

		}
	}(keyFile)
	//写入文件
	_, _ = keyFile.Write(kp)
}

// Encryption 加密函数
func Encryption(numStr string, encryptor bfv.Encryptor, encoder bfv.Encoder, plaintext *bfv.Plaintext) *bfv.Ciphertext {
	num, _ := strconv.Atoi(numStr)
	data := []int64{int64(num)}
	//将data编码为plaintext格式
	encoder.EncodeInt(data, plaintext)
	//加密
	ciphertext := encryptor.EncryptNew(plaintext)
	return ciphertext
}

// ExpressEncryption 加密表达式中的数字并且将密文存入文件
func ExpressEncryption(express string, pm bfv.Parameters, pk *rlwe.PublicKey) {
	//给表达式前后添加上括号
	if express[0] != '(' {
		express = "(" + express + ")"
	}
	//获取加密函数
	encryptor := bfv.NewEncryptor(pm, pk)
	//根据加密参数生成编码器
	encoder := bfv.NewEncoder(pm)
	//定义明文载体
	plaintext := bfv.NewPlaintext(pm)
	//时间戳(用于给文件命名)
	timeStamp := strconv.Itoa(int(time.Now().Unix()))
	exFile, _ := os.Create("./cipherFiles/cp_" + timeStamp + ".txt")
	defer func(exFile *os.File) {
		err := exFile.Close()
		if err != nil {
		}
	}(exFile)

	//运算逻辑处理(将表达式中的数字加密，符号不加密，存入文件)
	var exs Express
	exs.Nums = make(map[int]*bfv.Ciphertext)
	flag := true  //表示是个数字
	n := 0        //表示第几个数字
	numStr := " " //表示当前数字
	for i, ch := range express {
		switch ch {
		case '(', ')', '+', '-', '*':
			if numStr != " " {
				n++
				exs.Operators = append(exs.Operators, strconv.Itoa(n))
				//将数字加密后存入文件
				cpb := Encryption(numStr, encryptor, encoder, plaintext)
				exs.Nums[n] = cpb
				//_, _ = exFile.Write(cpb)
				numStr = " "
			}
			exs.Operators = append(exs.Operators, string(ch))
			//_, _ = exFile.WriteString(string(ch))
			flag = false
		default:
			if flag {
				numStr += string(ch)
			} else {
				numStr = string(ch)
			}
			if i == len(express)-1 {
				n++
				exs.Operators = append(exs.Operators, strconv.Itoa(n))
				cpb := Encryption(numStr, encryptor, encoder, plaintext)
				exs.Nums[n] = cpb
				//_, _ = exFile.Write(cpb)
			}
			flag = true
		}
	}
	//格式化后写入文件
	//fmt.Println(exs)
	exf, _ := json.Marshal(exs)
	_, _ = exFile.Write(exf)
}

// Decryption 解密
func Decryption(c *bfv.Ciphertext, pm bfv.Parameters, sk *rlwe.SecretKey) int64 {
	//根据参数和私钥生成解密函数和编码器
	decryptor := bfv.NewDecryptor(pm, sk)
	encoder := bfv.NewEncoder(pm)
	//用解密函数解密密文得到明文
	plaintext := decryptor.DecryptNew(c)
	//用编码器反编码得到最终明文
	result := encoder.DecodeIntNew(plaintext)
	return result[0]
}
