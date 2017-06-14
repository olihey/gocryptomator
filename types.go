package gocryptomator

import (
	"io/ioutil"
	"os"
	"time"

	"fmt"

	"path/filepath"

	"github.com/Sirupsen/logrus"
)

// CryptomatorNode handles the os.FIleInfo interface
type CryptomatorNode struct {
	fileInfo    os.FileInfo
	vault       *CryptomatorVault
	parentDirID string
}

func CreateNodeFromFileInfo(fileinfo os.FileInfo, vault *CryptomatorVault, parentDirID string) *CryptomatorNode {
	return &CryptomatorNode{fileInfo: fileinfo, vault: vault, parentDirID: parentDirID}
}

func (n *CryptomatorNode) Name() string {
	decryptedFilename, err := n.vault.DecryptFilename(n.fileInfo.Name(), n.parentDirID)
	if err != nil {
		logrus.Errorf("Error while decrypting filename '%s': %s", n.fileInfo.Name(), err)
		return n.fileInfo.Name()
	}
	return decryptedFilename
}
func (n *CryptomatorNode) Size() int64 {
	if n.IsDir() {
		return 0
	}
	return n.fileInfo.Size()
}
func (n *CryptomatorNode) Mode() os.FileMode {
	return n.fileInfo.Mode()
}
func (n *CryptomatorNode) ModTime() time.Time {
	return n.fileInfo.ModTime()
}
func (n *CryptomatorNode) IsDir() bool {
	return "0" == n.fileInfo.Name()[:1]
}
func (n *CryptomatorNode) Sys() interface{} {
	return n.vault
}
func (n *CryptomatorNode) DirUUID() (string, error) {
	if !n.IsDir() {
		return "", fmt.Errorf("%s is not a directory", n.Name())
	}

	fullPath, err := n.vault.EncryptedPathFor(n.parentDirID, true)
	if err != nil {
		return "", err
	}

	b, err := ioutil.ReadFile(filepath.Join(fullPath, n.fileInfo.Name()))
	if err != nil {
		return "", err
	}

	return string(b), nil
}
