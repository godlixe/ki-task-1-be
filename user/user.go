package user

import (
	"encoding/hex"
	"encryption/guard"
	"reflect"
	"slices"
)

// User represents a user entity.
type User struct {
	ID           uint64 `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PhoneNumber  string `json:"phoneNumber"`
	Gender       string `json:"gender"`
	Religion     string `json:"religion"`
	Nationality  string `json:"nationality"`
	Address      string `json:"address"`
	BirthInfo    string `json:"birth_info"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key"`
	KeyReference []byte `json:"key_reference"`
}

// Types for gender
const (
	Male   string = "male"
	Female string = "female"
)

var unencryptedFields []string = []string{"ID", "Username", "Password", "KeyReference"}

func (u *User) EncryptUserData(guard *guard.Guard, key []byte) error {
	var (
		userV  = reflect.ValueOf(*u)
		userEl = reflect.ValueOf(u).Elem()
	)

	for i := 0; i < userV.NumField(); i++ {
		field := userV.Type().Field(i).Name
		if !slices.Contains(unencryptedFields, field) && !userV.Field(i).IsZero() {
			value := userV.Field(i).Interface().(string)
			encryptedValue, err := guard.Encrypt(key, []byte(value))
			if err != nil {
				return err
			}
			userEl.Field(i).SetString(hex.EncodeToString(encryptedValue))
		}
	}

	return nil
}

func (u *User) DecryptUserData(guard *guard.Guard, key guard.Key) error {
	var (
		userV  = reflect.ValueOf(*u)
		userEl = reflect.ValueOf(u).Elem()
	)

	for i := 0; i < userV.NumField(); i++ {
		field := userV.Type().Field(i).Name
		if !slices.Contains(unencryptedFields, field) && !userV.Field(i).IsZero() {
			value := userV.Field(i).Interface().(string)

			hexValue, err := hex.DecodeString(value)

			decryptedValue, err := guard.Decrypt(key.PlainKey, []byte(hexValue))
			if err != nil {
				return err
			}

			userEl.Field(i).SetString(string(decryptedValue[:]))
		}
	}

	return nil
}
