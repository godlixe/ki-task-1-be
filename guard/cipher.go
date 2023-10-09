package guard

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type Repository interface {
	GetKey(ctx context.Context, table string, id uint64) (Key, error)
	StoreKey(ctx context.Context, table string, key Key) (Key, error)
}

// Guard is a cipher tool to encrypt, decrypt, and store keys
// depending on the mode. Available modes are :
//
// - AES : 1
// - RC4 : 2
// - DES : 3
type Guard struct {
	Mode        int
	MetadataKey []byte
	repository  Repository
}

// NewGuard creates a new guard with assigned fields.
func NewGuard(mode int, metadataKey []byte, repository Repository) *Guard {
	return &Guard{
		Mode:        mode,
		MetadataKey: metadataKey,
		repository:  repository,
	}
}

// Get gets the plain key
func (g *Guard) GetKey(ctx context.Context, table string, metadata []byte) (Key, error) {
	var err error
	keyRef, err := g.Decrypt(g.MetadataKey, metadata)
	if err != nil {
		return Key{}, err
	}

	key, err := g.repository.GetKey(ctx, table, binary.BigEndian.Uint64(keyRef))
	if err != nil {
		return Key{}, err
	}

	return key, nil
}

// StoreKey returns key metadata
func (g *Guard) StoreKey(ctx context.Context, table string, key Key) ([]byte, error) {
	key, err := g.repository.StoreKey(ctx, table, key)
	if err != nil {
		return nil, err
	}

	metadata, err := g.GenerateMetadata(key)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// GenerateMetadata generates a encrypted reference of the key.
func (g *Guard) GenerateMetadata(key Key) ([]byte, error) {
	keyRef := make([]byte, 8)

	binary.BigEndian.PutUint64(keyRef, key.id)

	metadata, err := g.Encrypt(g.MetadataKey, keyRef)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// GenerateKey generates a random key of length 32 bytes, or
// 8 bytes (for DES mode).
func (g *Guard) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	// Handle DES mode which requires 8-byte key
	if g.Mode == 3 {
		key = key[:8]
	}

	return key, nil
}

// Pad pads the data based on PKCS7 standards.
func (g *Guard) Pad(data []byte, blockSize int) []byte {
	padder := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padder)}, padder)
	return append(data, padding...)
}

// Unpad unpads the data based on PKCS7 standards.
func (g *Guard) Unpad(data []byte, blockSize int) []byte {
	length := len(data)
	unpadder := int(data[length-1])
	return data[:(length - unpadder)]
}

// Decrypt decrypts a data depending on the guard mode.
func (g *Guard) Decrypt(key []byte, data []byte) ([]byte, error) {
	switch g.Mode {
	// AES Mode
	case 1:
		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			return nil, err
		}

		nonceSize := gcm.NonceSize()

		nonce, data := data[:nonceSize], data[nonceSize:]
		res, err := gcm.Open(nil, nonce, data, nil)
		if err != nil {
			return nil, err
		}

		return res, nil
	// RC4 Mode
	case 2:
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}

		res := make([]byte, len(data))
		c.XORKeyStream(res, data)
		return res, nil
	// DES Mode
	case 3:
		c, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		res := make([]byte, 0)
		for len(data) > 0 {
			tmpRes := make([]byte, 8)
			c.Decrypt(tmpRes, data[:c.BlockSize()])
			data = data[c.BlockSize():]
			res = append(res, tmpRes...)
		}

		res = g.Unpad(res, c.BlockSize())

		return res, nil
	}

	return nil, errors.New("invalid guard mode")
}

// Encrypt encrypts a data depending on the guard mode.
func (g *Guard) Encrypt(key []byte, data []byte) ([]byte, error) {
	switch g.Mode {
	case 1:
		c, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, gcm.NonceSize())

		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Println(err)
			return nil, err
		}

		return gcm.Seal(nonce, nonce, data, nil), nil
	case 2:
		c, err := rc4.NewCipher(key)
		if err != nil {
			return nil, err
		}

		res := make([]byte, len(data))
		c.XORKeyStream(res, data)
		return res, nil
	case 3:
		c, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}

		data = g.Pad(data, c.BlockSize())

		res := make([]byte, 0)
		for len(data) > 0 {
			tmpRes := make([]byte, 8)
			c.Encrypt(tmpRes, data[:c.BlockSize()])
			data = data[c.BlockSize():]
			res = append(res, tmpRes...)
		}

		return res, nil
	}

	return nil, errors.New("invalid guard mode")
}
