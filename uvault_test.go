package uvault

import (
	"fmt"
	"os"
	"path"
	"testing"
)

func TestUserInfo(t *testing.T) {
	var vault Credential
	if err := vault.UserInfo("uvault", "uvault"); err != nil {
		t.Errorf(err.Error())
	}

	if path.Dir(vault.File) != vault.HomeDir+"/.local/uvault" {
		t.Errorf("%v vault directory will not work as it should", path.Dir(vault.File))
	}
}

func TestCreateVaultDir(t *testing.T) {
	var vault Credential
	if err := vault.UserInfo("uvault", "uvault"); err != nil {
		t.Errorf(err.Error())
	}

	if err := vault.setDir(); err != nil {
		t.Errorf(err.Error())
	}

	_, err := os.Stat(path.Dir(vault.File))
	if os.IsNotExist(err) {
		t.Errorf(err.Error())
	}
}

func TestSetInfo(t *testing.T) {
	var vault Credential
	t.Run(fmt.Sprintf("setting vault"), func(t *testing.T) {
		if err := vault.SetInfo("myUser", "myPass@#$%^&*", "https://xyz.ww/", "uvault", "uvault"); err != nil {
			t.Errorf(err.Error())
		}
	})

	t.Run(fmt.Sprintf("check if vault was created"), func(t *testing.T) {
		_, err := os.Stat(vault.File)
		if os.IsNotExist(err) {
			t.Errorf(err.Error())
		}
	})

}

func TestReadFile(t *testing.T) {
	var vault Credential
	if err := vault.ReadFile("uvault", "uvault"); err != nil {
		t.Errorf(err.Error())
	}

	if vault.APIKey != "myUser" {
		t.Errorf("expected myUser, got %v", vault.APIKey)

	}

	if vault.DecryptedKValue != "myPass@#$%^&*" {
		t.Errorf("expected myPass, got %v", vault.DecryptedKValue)
	}

	if vault.B64 != "bXlVc2VyOm15UGFzc0AjJCVeJio=" {
		t.Errorf("expected bXlVc2VyOm15UGFzc0AjJCVeJio=, got %v", vault.B64)
	}
}
