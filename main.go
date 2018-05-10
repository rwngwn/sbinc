package main

import (
	"io/ioutil"
	"os"
	"strings"

	"path/filepath"

	"syscall"

	"github.com/sirupsen/logrus"
)

func is_system_cmd(cmd string) bool {

	return filepath.IsAbs(cmd)
}

func main() {
	_, exist := os.LookupEnv("SBINC_DEBUG")
	if !exist {
		logrus.SetOutput(ioutil.Discard)
	}
	logrus.Infof("Runing with args: '%s'", os.Args)
	if !is_system_cmd(os.Args[1]) {
		logrus.Infof("'%s' is not a system binary -> containerizing", os.Args[1])
		containerize(os.Args[1:])
	} else {
		logrus.Info(os.Args[1])
		if strings.HasSuffix(os.Args[1], ".sh") {
			syscall.Exec("/bin/bash", os.Args, os.Environ())
		} else {
			syscall.Exec("/usr/bin/python", os.Args, os.Environ())
		}
	}

}
