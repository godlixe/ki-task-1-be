package file

import (
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

type FileService interface {
	listFiles(ctx context.Context, fileType string) ([]File, error)
	getFile(ctx context.Context, id uint64) ([]byte, error)
	storeFile(
		ctx context.Context,
		userID uint64,
		header multipart.FileHeader,
		file multipart.File,
		fileType string,
	) ([]byte, error)
	deleteFile(ctx context.Context, fileID uint64) error
}

type Handler struct {
	fileService FileService
}

func NewFileHandler(
	fs fileService,
) Handler {
	return Handler{
		fileService: &fs,
	}
}

func (h *Handler) UploadFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var fileType = r.FormValue("type")
	fileType, err := ValidateType(fileType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	uploadedFile, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer uploadedFile.Close()

	res, err := h.fileService.storeFile(context.TODO(), 1, *header, uploadedFile, fileType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Write(res)
}

func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {

	fileType := strings.TrimPrefix(r.URL.Path, "/files/")

	fileType, err := ValidateType(fileType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := h.fileService.listFiles(context.TODO(), fileType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	b, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func (h *Handler) GetFile(w http.ResponseWriter, r *http.Request) {

	qID := strings.TrimPrefix(r.URL.Path, "/file/")

	id, err := strconv.ParseUint(qID, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := h.fileService.getFile(context.TODO(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func (h *Handler) DeleteFile(w http.ResponseWriter, r *http.Request) {

	qID := strings.TrimPrefix(r.URL.Path, "/file/")

	id, err := strconv.ParseUint(qID, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.fileService.deleteFile(context.TODO(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("delete success"))
}
