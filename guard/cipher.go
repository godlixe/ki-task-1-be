package guard

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type Repository interface {
	GetKey(ctx context.Context, table string, id uint64) (Key, error)
	StoreKey(ctx context.Context, table string, key Key) (Key, error)
}

type Guard struct {
	Mode        int
	MetadataKey []byte
	repository  Repository
}

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

func (g *Guard) GenerateMetadata(key Key) ([]byte, error) {
	keyRef := make([]byte, 8)

	binary.BigEndian.PutUint64(keyRef, key.id)

	metadata, err := g.Encrypt(g.MetadataKey, keyRef)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func (g *Guard) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Decrypt decrypts a data depending on the guard mode
func (g *Guard) Decrypt(key []byte, data []byte) ([]byte, error) {
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
}

func (g *Guard) Encrypt(key []byte, data []byte) ([]byte, error) {
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
}
