package permission

import (
	"context"
	"encoding/json"
	"encryption/helper"
	"net/http"
	"strconv"
)

type PermissionService interface {
	GetNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]Notification, error)
}

type Handler struct {
	permissionService PermissionService
}

func NewPermissionHandler(
	ps permissionService,
) Handler {
	return Handler{
		permissionService: &ps,
	}
}

func (h *Handler) GetNotifications(w http.ResponseWriter, r *http.Request) {
	userID := uint64(r.Context().Value("user_id").(float64))
	var err error

	qStatus := r.URL.Query().Get("status")
	qDir := r.URL.Query().Get("dir")

	// converting and assinging default value if conversion errors
	status, err := strconv.Atoi(qStatus)
	if err != nil {
		status = 3
	}

	dir, err := strconv.Atoi(qDir)
	if err != nil {
		dir = 1
	}

	res, err := h.permissionService.GetNotifications(
		context.Background(),
		userID,
		status,
		dir,
	)
	if err != nil {
		response := helper.Response{
			Message: err.Error(),
			Data:    nil,
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	response := helper.Response{
		Data:    res,
		Message: "success",
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)
}
