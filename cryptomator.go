package gocryptomator

import (
	"crypto/cipher"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"

	"crypto/aes"

	"crypto/sha1"

	"github.com/Sirupsen/logrus"
	"github.com/jacobsa/crypto/siv"
	"golang.org/x/crypto/scrypt"
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
	kek                    []byte
	cipher                 cipher.Block
}

// ConvertToBytes converts all strings to the corresponding bytes values
func (mc *CryptomatorVault) ConvertToBytes() error {
	var err error
	mc.ScryptSalt, err = base64.StdEncoding.DecodeString(mc.ScryptSaltString)
	if err != nil {
		return fmt.Errorf("Error while decoding ScryptSalt string %s, err: %s", mc.ScryptSaltString, err)
	}
	mc.PrimaryMasterKey, err = base64.StdEncoding.DecodeString(mc.PrimaryMasterKeyString)
	if err != nil {
		return fmt.Errorf("Error while decoding PrimaryMasterKey string %s, err: %s", mc.PrimaryMasterKeyString, err)
	}
	mc.HmacMasterKey, err = base64.StdEncoding.DecodeString(mc.HmacMasterKeyString)
	if err != nil {
		return fmt.Errorf("Error while decoding HmacMasterKey string %s, err: %s", mc.HmacMasterKeyString, err)
	}
	mc.VersionMac, err = base64.StdEncoding.DecodeString(mc.VersionMacString)
	if err != nil {
		return fmt.Errorf("Error while decoding VersionMac string %s, err: %s", mc.VersionMacString, err)
	}

	return nil
}

// OpenCrytomatorVault opens an existing vault in the given directory
func OpenCrytomatorVault(vaultDirectory string, password []byte) (*CryptomatorVault, error) {
	masterKeyFilename := path.Join(vaultDirectory, CryptomatorMasterkey)
	logrus.Debugf("Trying to open %s\n", masterKeyFilename)

	raw, err := ioutil.ReadFile(masterKeyFilename)
	if err != nil {
		return nil, err
	}

	var vault CryptomatorVault
	err = json.Unmarshal(raw, &vault)
	if nil != err {
		logrus.Errorf("Unable to parse MaskerKey file")
		return nil, err
	}

	vault.vaultDirectory = vaultDirectory
	err = vault.ConvertToBytes()
	if err != nil {
		return nil, err
	}

	vault.kek, err = scrypt.Key(password, vault.ScryptSalt, vault.ScryptCostParam, vault.ScryptBlockSize, 1, 32)
	if err != nil {
		return nil, err
	}

	vault.cipher, err = aes.NewCipher(vault.kek)
	if err != nil {
		return nil, err
	}

	vault.HmacMasterKey, err = KeyUnwrap(vault.cipher, vault.HmacMasterKey)
	if err != nil {
		return nil, err
	}

	vault.PrimaryMasterKey, err = KeyUnwrap(vault.cipher, vault.PrimaryMasterKey)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("MasterKeyData: %v\n", vault)

	var asData [][]byte
	asData = append(asData, vault.HmacMasterKey)
	// dirIdHash := base32(sha1(aesSiv(dirId, null, encryptionMasterKey, macMasterKey)))
	rootDirNameData, err := siv.Encrypt(nil, append(vault.HmacMasterKey[:], vault.PrimaryMasterKey[:]...), []byte(""), nil)
	fmt.Println(rootDirNameData)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write(rootDirNameData)
	sha1Data := h.Sum(nil)
	fmt.Println(sha1Data)
	rootDirName := base32.StdEncoding.EncodeToString(sha1Data)
	fmt.Printf("Root dirname 1: %s\n", rootDirName)
	fmt.Println("Root dirname 2: ZFHPJQGVD3AH3WQNTOFRRRWVMYYNRPAX")

	// dirIdHash := base32(sha1(aesSiv(dirId, null, encryptionMasterKey, macMasterKey)))
	// dirPath := vaultRoot + '/d/' + substr(dirIdHash, 0, 2) + '/' + substr(dirIdHash, 2, 30)

	return &vault, nil
}
