package uvault_test

import (
	"fmt"

	"github.com/marco-ostaska/uvault"
)

func ExampleCredential_SetInfo() {
	var vCred uvault.Credential

	if err := vCred.SetInfo("myUser", "myPass@#$%^&*", "https://xyz.ww/", "uvault", "uvault"); err != nil {
		fmt.Println(err)
	}

}

func ExampleCredential_ReadFile() {
	var vCred uvault.Credential
	if err := vCred.ReadFile("uvault", "uvault"); err != nil {
		fmt.Println(err)
	}

	fmt.Println("User:", vCred.APIKey)
	fmt.Println("Pass:", vCred.DecryptedKValue)
	// Output:
	// User: myUser
	// Pass: myPass@#$%^&*

}
