# uvault
[![GoDoc](https://godoc.org/github.com/marco-ostaska/uvault?status.svg)](https://godoc.org/github.com/marco-ostaska/uvault)
[![Go Report Card](https://goreportcard.com/badge/github.com/marco-ostaska/uvault)](https://goreportcard.com/report/github.com/marco-ostaska/uvault)

    import "github.com/marco-ostaska/uvault"

Package uvault creates simple user vaults for credentials

## Usage

#### type Credential

```go
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
```

Credential is an abstraction to credential vault

#### func (*Credential) ReadFile

```go
func (c *Credential) ReadFile(dirVault, fileVault string) error
```
ReadFile reads the credential vault and unmarshal it.

#### func (*Credential) SetInfo

```go
func (c *Credential) SetInfo(apiKey, keyValue, url, dirVault, fileVault string) error
```
SetInfo set provided information to credential vault

apiKey and keyValue are the API key and Key Value (username and password in case
of Baic Auth)

#### func (*Credential) UserInfo

```go
func (c *Credential) UserInfo(dirVault, fileVault string) error
```
UserInfo parse HomeDir, Username, Hostname and File to vault.Credential
