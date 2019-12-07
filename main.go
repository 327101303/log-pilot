package main

import (
	"flag"
	"github.com/327101303/log-pilot/pilot"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
)

func main() {
	// 获取参数
	// 模板文件的路径
	template := flag.String("template", "", "Template filepath for fluentd or filebeat.")
	// 宿主机root目录挂载路径。期望是/host
	base := flag.String("base", "", "Directory which mount host root.")

	// log-level
	level := flag.String("log-level", "INFO", "Log level")

	flag.Parse() //解析参数

	// 返回挂载路径的绝对路径，并保证路径是唯一的
	baseDir, err := filepath.Abs(*base)
	if err != nil {
		panic(err)
	}
	// 如果basedir为根路径，重新赋值为空
	if baseDir == "/" {
		baseDir = ""
	}
	// 如果模板路径为空直接panic
	if *template == "" {
		panic("template file can not be empty")
	}

	// 设定log的输出流为标准输出
	log.SetOutput(os.Stdout)
	// 解析传参中的loglevel
	logLevel, err := log.ParseLevel(*level)
	// 如果解析该参数出错，panic
	if err != nil {
		panic(err)
	}
	// 设置loglevel为传参中的loglevel
	log.SetLevel(logLevel)
	// 读取模板文件
	b, err := ioutil.ReadFile(*template)
	if err != nil {
		panic(err)
	}
	//把模板文件和根路径传参给pilot的Run方法
	log.Fatal(pilot.Run(string(b), baseDir))
}
