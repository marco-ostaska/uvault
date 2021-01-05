// Package uvault creates simple user vaults for credentials
package uvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
)

const vaultFile string = "/.local/"

// Credential is an abstraction to credential vault
type Credential struct {
	HomeDir         string // local user home directory
	Username        string // local user name
	Hostname        string // local hostname
	File            string // credential vault file full path
	CryptedKValue   string // encrypted API password or API key value
	DecryptedKValue string // decrypted API password or API key valeu
	CryptJSON       string
	DcryptJSON      string
	B64             string `json:"b64"` // base64 mask to be used by API calls
	APIKey          string `json:"key"` // APIKey, may be used for APIkey, username, in case of basic auth
	URL             string `json:"url"` // API URL
}

// UserInfo parse HomeDir, Username, Hostname and File to vault.Credential
func (c *Credential) UserInfo(dirVault, fileVault string) error {
	usr, err := user.Current()
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	c.HomeDir = usr.HomeDir
	c.Username = usr.Username
	c.Hostname = hostname
	c.File = fmt.Sprintf("%s/%s/%s/%s", usr.HomeDir, vaultFile, dirVault, fileVault)

	return nil
}

// SetInfo set provided information to credential vault
//
// apiKey and keyValue are the API key and Key Value (username and password in case of Baic Auth)
//
func (c *Credential) SetInfo(apiKey, keyValue, url, dirVault, fileVault string) error {
	if err := c.UserInfo(dirVault, fileVault); err != nil {
		return err
	}
	c.URL = url
	c.APIKey = apiKey
	err := c.setDir()
	if err != nil {
		return err
	}

	enc, err := c.encrypt(keyValue)
	if err != nil {
		return err
	}

	c.CryptedKValue = enc

	err = c.apiB64(c.APIKey, c.CryptedKValue)
	if err != nil {
		return err
	}

	err = c.toJSON()
	if err != nil {
		return err
	}

	return nil
}

// ReadFile reads the credential vault and unmarshal it.
func (c *Credential) ReadFile(dirVault, fileVault string) error {
	if err := c.UserInfo(dirVault, fileVault); err != nil {
		return err
	}
	data, err := ioutil.ReadFile(c.File)
	if err != nil {
		return err
	}

	sDec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}

	bs, err := c.decrypt(string(sDec))
	if err != nil {
		return err
	}

	err = json.Unmarshal(bs, &c)
	if err != nil {
		return err
	}
	return nil

}

// getHash genetares a 32 char hash based on user
// machine and sha512 information
func getHash(s string) (bs []byte, err error) {
	hash := sha512.New()
	if _, err = hash.Write([]byte(s)); err != nil {
		return bs, err
	}

	bs = []byte(hex.EncodeToString(hash.Sum(nil))[:32])
	return bs, nil
}

func (c *Credential) setDir() error {
	return os.MkdirAll(path.Dir(c.File), 0700)
}

func (c *Credential) newGCM() (gcm cipher.AEAD, err error) {
	hash, err := getHash(c.HomeDir + c.Username + c.Hostname)
	if err != nil {
		return gcm, err
	}

	cBlock, err := aes.NewCipher(hash)
	if err != nil {
		return gcm, err
	}

	return cipher.NewGCM(cBlock)

}

// encrypt encrypts the content
func (c *Credential) encrypt(s string) (string, error) {
	data := []byte(s)
	gcm, err := c.newGCM()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	enc := gcm.Seal(nonce, nonce, data, nil)

	return base64.StdEncoding.EncodeToString(enc), nil
}

// decrypt descrypts the content
func (c *Credential) decrypt(s string) (bs []byte, err error) {
	data := []byte(s)
	gcm, err := c.newGCM()
	if err != nil {
		return bs, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	ptxt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return bs, err
	}

	return ptxt, err

}

// apiB64 mask the encrypted content to base64
func (c *Credential) apiB64(apiKey, keyValue string) error {
	sDec, err := base64.StdEncoding.DecodeString(keyValue)
	if err != nil {
		return err
	}

	bs, err := c.decrypt(string(sDec))
	if err != nil {
		return err
	}

	c.DecryptedKValue = string(bs)
	up := apiKey + ":" + c.DecryptedKValue
	c.B64 = base64.StdEncoding.EncodeToString([]byte(up))
	return nil
}

// toJSON marshal to json for easy manipulation of the data
func (c *Credential) toJSON() error {
	bs, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f, err := os.Create(c.File)

	if err != nil {
		return err
	}

	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	if err != nil {
		return err
	}
	enc, err := c.encrypt(string(bs))
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(enc))
	if err != nil {
		return err
	}

	if err := os.Chmod(c.File, 0600); err != nil {
		return err
	}
	return nil
}
