package gocryptomator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

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
	hmacAndMasterKey       []byte
	vaultDirectory         string
	kek                    []byte
	cipher                 cipher.Block
	sha1Hasher             hash.Hash
	rootDirectory          string
}

// prepareFromMasterKeyData converts all strings to the corresponding bytes values
func (vault *CryptomatorVault) prepareFromMasterKeyData(raw []byte, vaultDirectory string, password []byte) error {
	// first convert all strings to bytes
	var err error

	// decrypt the keys
	err = json.Unmarshal(raw, &vault)
	if nil != err {
		logrus.Errorf("Unable to parse MaskerKey file")
		return err
	}

	// convert the base64 strings into byte slices
	vault.ScryptSalt, err = base64.StdEncoding.DecodeString(vault.ScryptSaltString)
	if err != nil {
		return fmt.Errorf("Error while decoding ScryptSalt string %s, err: %s", vault.ScryptSaltString, err)
	}
	vault.PrimaryMasterKey, err = base64.StdEncoding.DecodeString(vault.PrimaryMasterKeyString)
	if err != nil {
		return fmt.Errorf("Error while decoding PrimaryMasterKey string %s, err: %s", vault.PrimaryMasterKeyString, err)
	}
	vault.HmacMasterKey, err = base64.StdEncoding.DecodeString(vault.HmacMasterKeyString)
	if err != nil {
		return fmt.Errorf("Error while decoding HmacMasterKey string %s, err: %s", vault.HmacMasterKeyString, err)
	}
	vault.VersionMac, err = base64.StdEncoding.DecodeString(vault.VersionMacString)
	if err != nil {
		return fmt.Errorf("Error while decoding VersionMac string %s, err: %s", vault.VersionMacString, err)
	}

	// save the name of the directory
	vault.vaultDirectory = vaultDirectory

	// create the KEK to decrypt the keys
	vault.kek, err = scrypt.Key(password, vault.ScryptSalt, vault.ScryptCostParam, vault.ScryptBlockSize, 1, 32)
	if err != nil {
		return err
	}
	vault.cipher, err = aes.NewCipher(vault.kek)
	if err != nil {
		return err
	}

	// unwrap the keys using the KEK
	vault.HmacMasterKey, err = KeyUnwrap(vault.cipher, vault.HmacMasterKey)
	if err != nil {
		return err
	}
	vault.PrimaryMasterKey, err = KeyUnwrap(vault.cipher, vault.PrimaryMasterKey)
	if err != nil {
		return err
	}

	// append the hmac and the masterkey to be used in the AES SIV routine
	vault.hmacAndMasterKey = append(vault.HmacMasterKey[:], vault.PrimaryMasterKey[:]...)

	return nil
}

// EncryptedPathFor returns the encrypted path for a given uuid
func (vault *CryptomatorVault) EncryptedPathFor(uuid string, fullPath bool) (string, error) {
	// encrypt the uuid string
	rootDirNameData, err := siv.Encrypt(nil, vault.hmacAndMasterKey, []byte(uuid), nil)
	if err != nil {
		return "", err
	}

	// encode it into a string
	dirname := base32.StdEncoding.EncodeToString(vault.hashSHA1(rootDirNameData))

	// return ...
	if fullPath {
		// ... a full path
		return filepath.Join(vault.vaultDirectory, "d", dirname[:2], dirname[2:]), nil
	}
	// just the part into the vault
	return path.Join("d", dirname[:2], dirname[2:]), nil
}

// hashSHA1 returns a SHA1 hash from a given byte slice
func (vault *CryptomatorVault) hashSHA1(payload []byte) []byte {
	vault.sha1Hasher.Reset()
	vault.sha1Hasher.Write(payload)
	return vault.sha1Hasher.Sum(nil)
}

// EncryptFilename returns the decrypted filenames
func (vault *CryptomatorVault) EncryptFilename(plainFilename string, parentDirID string) (string, error) {
	var associatedData = [][]byte{[]byte(parentDirID)}
	encryptedFilename, err := siv.Encrypt(nil, vault.hmacAndMasterKey, []byte(plainFilename), associatedData)
	if err != nil {
		return "", err
	}

	// encode it into a string
	return base32.StdEncoding.EncodeToString(encryptedFilename), nil
}

// EncryptDirectoryName returns the decrypted filenames
func (vault *CryptomatorVault) EncryptDirectoryName(plainFilename string, parentDirID string) (string, error) {
	encryptedFilename, err := vault.EncryptFilename(plainFilename, parentDirID)
	if err != nil {
		return "", err
	}

	return "0" + encryptedFilename, nil
}

// DecryptFilename returns the decrypted filenames
func (vault *CryptomatorVault) DecryptFilename(encryptedFilename string, parentDirID string) (string, error) {
	if encryptedFilename[:1] == "0" {
		encryptedFilename = encryptedFilename[1:]
	}

	var associatedData = [][]byte{[]byte(parentDirID)}

	filenameBytes, err := base32.StdEncoding.DecodeString(encryptedFilename)
	if err != nil {
		return "", err
	}

	filenameBytes, err = siv.Decrypt(vault.hmacAndMasterKey, filenameBytes, associatedData)
	if err != nil {
		return "", err
	}

	// base32(aesSiv(cleartextName, parentDirId, encryptionMasterKey, macMasterKey))

	return string(filenameBytes), nil
}

// ReadDir returns the decrypted filenames
func (vault *CryptomatorVault) ReadDir(path string) ([]os.FileInfo, error) {
	// pathComponents := strings.Split(path, "/")
	// for
	return nil, fmt.Errorf("Not implemented")
}

// List returns a list of FileInfo for the given UUID
func (vault *CryptomatorVault) List(pathUUID string) ([]*CryptomatorNode, error) {
	encryptedPath, err := vault.EncryptedPathFor(pathUUID, true)
	if err != nil {
		return nil, err
	}
	fmt.Println(encryptedPath)

	dirItems, err := ioutil.ReadDir(encryptedPath)
	if err != nil {
		return nil, err
	}

	var nodesList []*CryptomatorNode
	for _, dirItem := range dirItems {
		nodesList = append(nodesList, CreateNodeFromFileInfo(dirItem, vault, pathUUID))
	}
	return nodesList, nil
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
	err = vault.prepareFromMasterKeyData(raw, vaultDirectory, password)
	if err != nil {
		return nil, err
	}

	vault.sha1Hasher = sha1.New()

	vault.rootDirectory, err = vault.EncryptedPathFor("", false)
	if err != nil {
		return nil, err
	}

	return &vault, nil
}
