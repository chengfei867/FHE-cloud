package utils

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/tuneinsight/lattigo/v3/bfv"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"
)

// Express 表达式结构体
type Express struct {
	//存放操作符
	Operators []string
	//存放密文数字
	Nums map[int]*bfv.Ciphertext
}

// SaveFile 保存文件
func SaveFile(c *gin.Context, name string, dest string) (string, int64) {
	file, _ := c.FormFile(name)
	dst := path.Join("./files/"+dest, file.Filename)
	saveErr := c.SaveUploadedFile(file, dst)
	if saveErr != nil {
		c.JSON(http.StatusOK, saveErr.Error())
	}
	return file.Filename, file.Size
}

// ParseCpFile 密文解析&计算
func ParseCpFile(filename string, filesize int64, evaluator bfv.Evaluator) {
	file, _ := os.Open("./files/calFiles/" + filename)
	defer file.Close()
	buffer := make([]byte, filesize)
	_, _ = file.Read(buffer)
	var exs Express
	json.Unmarshal(buffer, &exs)
	//优先级
	priority := map[string]int{
		"(": 0,
		"+": 1,
		"-": 1,
		"*": 2,
		")": 3,
	}
	//操作符栈
	var optStack []string
	//操作数栈
	var numStack []*bfv.Ciphertext
	for _, operator := range exs.Operators {
		switch operator {
		case "(":
			optStack = append(optStack, operator)
		case "+", "-", "*":
			//当符号栈不为空并且当前优先级较低时
			for len(optStack) != 0 && (priority[operator] < priority[optStack[len(optStack)-1]]) {
				//从栈顶取出两个数字
				c1 := numStack[len(numStack)-2]
				c2 := numStack[len(numStack)-1]
				var c3 *bfv.Ciphertext
				//取出运算符
				op := optStack[len(optStack)-1]
				//出栈
				numStack = numStack[:len(numStack)-2]
				optStack = optStack[:len(optStack)-1]
				switch op {
				case "+":
					c3 = evaluator.AddNew(c1, c2)
				case "-":
					c3 = evaluator.SubNew(c1, c2)
				case "*":
					c3 = evaluator.MulNew(c1, c2)
				}
				numStack = append(numStack, c3)
			}
			optStack = append(optStack, operator)
		case ")":
			for optStack[len(optStack)-1] != "(" {
				//从栈顶取出两个数字
				c1 := numStack[len(numStack)-2]
				c2 := numStack[len(numStack)-1]
				var c3 *bfv.Ciphertext
				//取出运算符
				op := optStack[len(optStack)-1]
				//出栈
				numStack = numStack[:len(numStack)-2]
				optStack = optStack[:len(optStack)-1]
				switch op {
				case "+":
					c3 = evaluator.AddNew(c1, c2)
				case "-":
					c3 = evaluator.SubNew(c1, c2)
				case "*":
					c3 = evaluator.MulNew(c1, c2)
				}
				numStack = append(numStack, c3)
			}
			//将"("弹出
			optStack = optStack[:len(optStack)-1]
		default:
			idx, _ := strconv.Atoi(operator)
			numStack = append(numStack, exs.Nums[idx])
		}
	}
	//遍历操作符栈直至为空
	for len(optStack) != 0 {
		//从栈顶取出两个数字
		c1 := numStack[len(numStack)-2]
		c2 := numStack[len(numStack)-1]
		var c3 *bfv.Ciphertext
		//取出运算符
		op := optStack[len(optStack)-1]

		//出栈
		numStack = numStack[:len(numStack)-2]
		optStack = optStack[:len(optStack)-1]
		switch op {
		case "+":
			c3 = evaluator.AddNew(c1, c2)
		case "-":
			c3 = evaluator.SubNew(c1, c2)
		case "*":
			c3 = evaluator.MulNew(c1, c2)
		}
		numStack = append(numStack, c3)
	}
	//数字栈中存放着最后计算的结果
	c := numStack[0]
	//将计算结果重线性化
	result := evaluator.RelinearizeNew(c)
	//将计算结果密文存入文件
	timeStamp := strconv.Itoa(int(time.Now().Unix()))
	exFile, _ := os.OpenFile("./files/resultFiles/re_"+timeStamp+".txt", os.O_CREATE|os.O_APPEND, 0777)
	bytes, _ := json.Marshal(result)
	_, _ = exFile.Write(bytes)
}

// FHECal 全同态计算
func FHECal(calName string, calSize int64, pm bfv.Parameters, rk *rlwe.RelinearizationKey) {
	//根据pm和rk得到计算函数
	evaluator := bfv.NewEvaluator(pm, rlwe.EvaluationKey{Rlk: rk})
	//解析密文文件并且进行同态计算
	ParseCpFile(calName, calSize, evaluator)
}
