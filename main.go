package main

import (
	"encryption/database"
	"encryption/file"
	"encryption/guard"
	"fmt"
	"net/http"
	"os"
	"strconv"

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

	guardMode, _ := strconv.Atoi(os.Getenv("GUARD_MODE"))
	guard := guard.NewGuard(
		guardMode,
		[]byte(os.Getenv("GUARD_KEY")),
		guardRepository,
	)

	fileSystem := file.NewFileSystem()

	fileService := file.NewFileService(fileSystem, fileRepository, *guard)
	fileHandler := file.NewFileHandler(fileService)

	http.HandleFunc("/file/", fileHandler.GetFile)
	http.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			fileHandler.UploadFile(w, r)
		case "DELETE":

		}
	})

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
