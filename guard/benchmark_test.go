package guard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
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

func BenchmarkAESText(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 1}
	guard := NewGuard(1, []byte("12345678912345678912345678900000"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	var (
		cipher []byte
		err    error
	)

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkDESText(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 2}
	guard := NewGuard(2, []byte("12345678912345678912345678900000"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
	var (
		cipher []byte
		err    error
	)

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkRC4Text(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 3}
	guard := NewGuard(3, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	data := "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"

	var (
		cipher []byte
		err    error
	)

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkAESImage(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 1}
	guard := NewGuard(1, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/tux.png")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}
func BenchmarkRC4Image(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 2}
	guard := NewGuard(2, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/tux.png")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}
func BenchmarkDESImage(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 3}
	guard := NewGuard(3, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/tux.png")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkAESPDF(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 1}
	guard := NewGuard(1, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/gnu-c-manual.pdf")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkRC4PDF(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 2}
	guard := NewGuard(2, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/gnu-c-manual.pdf")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkDESPDF(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 3}
	guard := NewGuard(3, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/gnu-c-manual.pdf")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}

func BenchmarkAESVideo(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 1}
	guard := NewGuard(1, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/deep_blue.mp4")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}
func BenchmarkRC4Video(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 2}
	guard := NewGuard(2, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/deep_blue.mp4")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}
func BenchmarkDESVideo(b *testing.B) {
	guardRepo := MockGuardRepo{GuardMode: 3}
	guard := NewGuard(3, []byte("12345"), &guardRepo)
	key, _ := guardRepo.GetKey(context.Background(), "", 1)

	var (
		cipher []byte
		err    error
	)

	data, err := os.ReadFile("./test_files/deep_blue.mp4")
	if err != nil {
		log.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		cipher, err = guard.Encrypt(key.PlainKey, []byte(data))
		if err != nil {
			log.Fatal(err)
		}
	}

	encryptTime := b.Elapsed()

	for n := 0; n < b.N; n++ {

		_, err = guard.Decrypt(key.PlainKey, cipher)
		if err != nil {
			log.Fatal(err)
		}
	}

	decryptTime := b.Elapsed() - encryptTime

	fmt.Println("number of iterations: ", b.N)
	fmt.Printf("elapsed : %v (encryption) %v (decryption)\n", encryptTime, decryptTime)
}
