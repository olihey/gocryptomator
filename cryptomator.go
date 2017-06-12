package gocryptomator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/Sirupsen/logrus"
)

const (
	// CryptomatorMasterkey is the default filename for a vault related data
	CryptomatorMasterkey = "masterkey.cryptomator"
)

// CryptomatorVault holds the data for a Cryptomator vault
type CryptomatorVault struct {
	Version                int    `json:"version"`
	ScryptSaltString       string `json:"scryptSalt"`
	ScryptSalt             []byte
	ScryptCostParam        int    `json:"scryptCostParam"`
	ScryptBlockSize        int    `json:"scryptBlockSize"`
	PrimaryMasterKeyString string `json:"primaryMasterKey"`
	PrimaryMasterKey       []byte
	HmacMasterKeyString    string `json:"hmacMasterKey"`
	HmacMasterKey          []byte
	VersionMacString       string `json:"versionMac"`
	VersionMac             []byte
	vaultDirectory         string
}

// ConvertToBytes converts all strings to the corresponding bytes values
func (mc *CryptomatorVault) ConvertToBytes() {
	var err error
	mc.ScryptSalt, err = base64.StdEncoding.DecodeString(mc.ScryptSaltString)
	if err != nil {
		logrus.Errorf("Error while decoding ScryptSalt string %s, err: %s", mc.ScryptSaltString, err)
	}
	mc.PrimaryMasterKey, err = base64.StdEncoding.DecodeString(mc.PrimaryMasterKeyString)
	if err != nil {
		logrus.Errorf("Error while decoding PrimaryMasterKey string %s, err: %s", mc.PrimaryMasterKeyString, err)
	}
	mc.HmacMasterKey, err = base64.StdEncoding.DecodeString(mc.HmacMasterKeyString)
	if err != nil {
		logrus.Errorf("Error while decoding HmacMasterKey string %s, err: %s", mc.HmacMasterKeyString, err)
	}
	mc.VersionMac, err = base64.StdEncoding.DecodeString(mc.VersionMacString)
	if err != nil {
		logrus.Errorf("Error while decoding VersionMac string %s, err: %s", mc.VersionMacString, err)
	}
}

// OpenCrytomatorVault opens an existing vault in the given directory
func OpenCrytomatorVault(vaultDirectory string) (*CryptomatorVault, error) {
	masterKeyFilename := path.Join(vaultDirectory, CryptomatorMasterkey)
	fmt.Printf("Trying to open %s", masterKeyFilename)

	raw, err := ioutil.ReadFile(masterKeyFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	var vault CryptomatorVault
	err = json.Unmarshal(raw, &vault)
	if nil != err {
		logrus.Errorf("Unable to parse MaskerKey file")
		return nil, err
	}

	vault.vaultDirectory = vaultDirectory

	fmt.Printf("MasterKeyData: %v", vault)

	return &vault, nil
}