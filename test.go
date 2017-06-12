package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/olihey/gocryptomator"
)

func main() {
	_, err := gogryptomator.OpenCrytomatorVault("C:\\Users\\olihey\\Documents\\vault")
	if err != nil {
		logrus.Errorf("Failed to open vault: %s", err)
	}
}
