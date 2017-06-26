package gocryptomator

import (
	"io/ioutil"
	"os"
	"time"

	"fmt"

	"path/filepath"

	"github.com/Sirupsen/logrus"
)

const (
	CRYPTOMATOR_HEADER_SIZE       = 88
	CRYPTOMATOR_BLOCK_HEADER_SIZE = 48
	CRYPTOMATOR_BLOCK_SIZE        = 32 * 1024
	CRYPTOMATOR_FULL_BLOCK_SIZE   = CRYPTOMATOR_BLOCK_HEADER_SIZE + CRYPTOMATOR_BLOCK_SIZE
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

	// get the size of the fuile
	encryptedSize := n.fileInfo.Size()

	// deduct the header
	decryptedSize := encryptedSize - CRYPTOMATOR_HEADER_SIZE

	// Get the size of the last block
	lastBlockSize := decryptedSize % CRYPTOMATOR_FULL_BLOCK_SIZE

	// get the number of blocks the file is split into
	var blockCount int64
	if lastBlockSize == 0 {
		blockCount = decryptedSize / CRYPTOMATOR_FULL_BLOCK_SIZE
	} else {
		// if the last block is not FULL add it to the count
		blockCount = 1 + (decryptedSize / CRYPTOMATOR_FULL_BLOCK_SIZE)
	}
	// deduct the block headers for all blocks
	decryptedSize -= blockCount * CRYPTOMATOR_BLOCK_HEADER_SIZE

	return decryptedSize
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
