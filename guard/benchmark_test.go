package guard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"testing"
)

type MockGuardRepo struct {
	GuardMode int
}

func (m *MockGuardRepo) GetKey(ctx context.Context, table string, id uint64) (Key, error) {
	switch m.GuardMode {
	case 1, 2:
		return Key{1, []byte("12345678912345678912345678900000")}, nil
	case 3:
		return Key{1, []byte("12345678")}, nil
	}
	return Key{}, errors.New("invalid mode")
}

func (m *MockGuardRepo) StoreKey(ctx context.Context, table string, key Key) (Key, error) {
	switch m.GuardMode {
	case 1, 2:
		return Key{1, []byte("12345678912345678912345678900000")}, nil
	case 3:
		return Key{1, []byte("12345678")}, nil
	}
	return Key{}, errors.New("invalid mode")
}

func BenchmarkAES(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 1}
	guard := NewGuard(1, []byte("12345678912345678912345678900000"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	for n := 0; n < b.N; n++ {
		cipher, err := guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("number of iterations: ", b.N)
	fmt.Println("elapsed:", b.Elapsed())
}

func BenchmarkDES(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 2}
	guard := NewGuard(2, []byte("12345678912345678912345678900000"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	for n := 0; n < b.N; n++ {
		cipher, err := guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("number of iterations: ", b.N)
	fmt.Println("elapsed:", b.Elapsed())
}

func BenchmarkRC4(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 3}
	guard := NewGuard(3, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	for n := 0; n < b.N; n++ {
		cipher, err := guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("number of iterations: ", b.N)
	fmt.Println("elapsed:", b.Elapsed())
}
