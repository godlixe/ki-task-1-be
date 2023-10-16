package main

import (
	"encryption/database"
	"encryption/file"
	"encryption/guard"
	"encryption/request"
	"encryption/user"
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

	userRepository := user.NewUserRepository(db)
	fileRepository := file.NewFileRepository(db)
	guardRepository := guard.NewGuardRepository(db)

	guardMode, _ := strconv.Atoi(os.Getenv("GUARD_MODE"))
	guard := guard.NewGuard(
		guardMode,
		[]byte(os.Getenv("GUARD_KEY")),
		guardRepository,
	)

	userService := user.NewFileService(userRepository, *guard)
	userHandler := user.NewUserHandler(userService)

	fileSystem := file.NewFileSystem()

	fileService := file.NewFileService(fileSystem, fileRepository, *guard)
	fileHandler := file.NewFileHandler(fileService)

	mux := http.DefaultServeMux

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			userHandler.Login(w, r)
		}
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			userHandler.Register(w, r)
		}
	})

	mux.Handle("/profile", request.AuthMiddleware(http.HandlerFunc(userHandler.GetProfile)))

	mux.HandleFunc("/file/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fileHandler.GetFile(w, r)
		case "DELETE":
			fileHandler.DeleteFile(w, r)
		}
	})
	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			fileHandler.UploadFile(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	})
	mux.HandleFunc("/files/", fileHandler.ListFiles)

	var handler http.Handler = mux

	handler = request.CORSMiddleware(handler)

	err = http.ListenAndServe(":8080", handler)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
