package main

import (
	"encryption/database"
	"encryption/file"
	"encryption/guard"
	"fmt"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(os.Getenv("DB_HOST"))
	db, err := database.NewPostgresClient(
		database.DatabaseCredentials{
			Host:     os.Getenv("DB_HOST"),
			User:     os.Getenv("DB_USER"),
			Password: os.Getenv("DB_PASS"),
			Port:     os.Getenv("DB_PORT"),
			DBName:   os.Getenv("DB_NAME"),
		},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fileRepository := file.NewFileRepository(db)
	guardRepository := guard.NewGuardRepository(db)

	guard := guard.NewGuard(1, []byte("12345678912345678912345678900000"), guardRepository)

	fileSystem := file.NewFileSystem()

	fileService := file.NewFileService(fileSystem, fileRepository, *guard)
	fileHandler := file.NewFileHandler(fileService)

	http.HandleFunc("/get/", fileHandler.GetFile)
	http.HandleFunc("/post", fileHandler.UploadFile)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
