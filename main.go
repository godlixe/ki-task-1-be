package main

import (
	"encryption/cache"
	"encryption/database"
	"encryption/file"
	"encryption/guard"
	"encryption/request"
	"encryption/user"
	"encryption/user/decrypt"
	filepermission "encryption/user/file_permission"
	"encryption/user/permission"
	"encryption/user/profile"
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

	guardDB, err := database.NewPostgresClient(
		database.DatabaseCredentials{
			Host:     os.Getenv("GUARD_DB_HOST"),
			User:     os.Getenv("GUARD_DB_USER"),
			Password: os.Getenv("GUARD_DB_PASS"),
			Port:     os.Getenv("GUARD_DB_PORT"),
			DBName:   os.Getenv("GUARD_DB_NAME"),
		},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	redisClient := cache.NewRedisClient()

	userRepository := user.NewUserRepository(db)
	fileRepository := file.NewFileRepository(db)
	permissionRepository := permission.NewPermissionRepository(db)
	filePermissionRepository := filepermission.NewPermissionRepository(db)
	guardRepository := guard.NewGuardRepository(guardDB)

	guardMode, _ := strconv.Atoi(os.Getenv("GUARD_MODE"))
	guard := guard.NewGuard(
		guardMode,
		[]byte(os.Getenv("GUARD_KEY")),
		guardRepository,
	)

	userService := user.NewFileService(userRepository, *guard)
	userHandler := user.NewUserHandler(userService)

	fileSystem := file.NewFileSystem()

	decryptService := decrypt.NewDecryptService(
		fileRepository,
		fileSystem,
		*redisClient,
		guard,
	)

	permissionService := permission.NewPermissionService(decryptService, fileSystem, filePermissionRepository, permissionRepository, userRepository, *guard, userService)
	permissionHandler := permission.NewPermissionHandler(permissionService)

	fileService := file.NewFileService(filePermissionRepository, permissionService, *redisClient, userService, fileSystem, fileRepository, *guard)
	fileHandler := file.NewFileHandler(fileService)

	profileService := profile.NewProfileService(*redisClient, userService, userRepository, permissionRepository, *guard)
	profileHandler := profile.NewUserHandler(profileService)

	mux := http.DefaultServeMux

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			userHandler.Login(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			userHandler.Register(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))

		}
	})

	baseProfileRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			userHandler.GetProfile(w, r)
		case "PUT":
			userHandler.UpdateProfile(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}
	mux.Handle("/profile", request.AuthMiddleware(http.HandlerFunc(baseProfileRoutes)))

	profileRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			profileHandler.GetUserProfile(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}
	mux.Handle("/profile/", request.AuthMiddleware(http.HandlerFunc(profileRoutes)))

	subFileRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fileHandler.GetFile(w, r)
		case "DELETE":
			fileHandler.DeleteFile(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}

	mux.Handle("/file/", request.AuthMiddleware(http.HandlerFunc(subFileRoutes)))

	fileRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			fileHandler.UploadFile(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}

	mux.Handle("/file", request.AuthMiddleware(http.HandlerFunc(fileRoutes)))

	mux.Handle("/files/", request.AuthMiddleware(http.HandlerFunc(fileHandler.ListFiles)))

	permissionRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			permissionHandler.RequestPermission(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}

	mux.Handle("/request/list", request.AuthMiddleware(http.HandlerFunc(permissionHandler.GetNotifications)))
	mux.Handle("/request/", request.AuthMiddleware(http.HandlerFunc(permissionRoutes)))

	permissionActionRoutes := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			permissionHandler.RespondPermissionRequest(w, r)
		case "OPTIONS":
			w.Write([]byte("success"))
		}
	}

	mux.Handle("/request/action/", request.AuthMiddleware(http.HandlerFunc(permissionActionRoutes)))

	var handler http.Handler = mux

	handler = request.CORSMiddleware(handler)

	port := fmt.Sprintf(":%v", os.Getenv("APP_PORT"))
	if port == ":" {
		port = ":8080"
	}

	err = http.ListenAndServe(port, handler)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
