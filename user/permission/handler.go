package permission

import (
	"context"
	"encoding/json"
	"encryption/helper"
	"net/http"
	"strconv"
	"strings"
)

type PermissionService interface {
	GetNotifications(
		ctx context.Context,
		userID uint64,
		status int,
		direction int,
	) ([]Notification, error)

	RequestPermission(
		context.Context,
		RequestPermissionRequest,
	) (*RequestPermissionResponse, error)

	RespondPermissionRequest(
		context.Context,
		RespondPermissionRequestRequest,
	) (*RespondPermissionRequestResponse, error)
}

type Handler struct {
	permissionService PermissionService
}

func NewPermissionHandler(
	ps PermissionService,
) Handler {
	return Handler{
		permissionService: ps,
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

func (h *Handler) RequestPermission(w http.ResponseWriter, r *http.Request) {
	var (
		request RequestPermissionRequest
		err     error
	)

	qFileID := r.URL.Query().Get("file_id")
	fileID, err := strconv.ParseUint(qFileID, 10, 64)
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

	userID := uint64(r.Context().Value("user_id").(float64))
	username := strings.TrimPrefix(r.URL.Path, "/request/")

	request = RequestPermissionRequest{
		UserID:         userID,
		TargetUsername: username,
		FileID:         fileID,
	}

	_, err = h.permissionService.RequestPermission(context.Background(), request)
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
		Message: "Request successfully sent",
	}

	w.Header().Set("content-type", "application/json")

	if err != nil {
		response.Message = err.Error()
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResponse)
}

func (h *Handler) RespondPermissionRequest(w http.ResponseWriter, r *http.Request) {
	var (
		request RespondPermissionRequestRequest
		err     error
	)

	w.Header().Set("content-type", "application/json")

	err = json.NewDecoder(r.Body).Decode(&request)
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

		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	err = request.Validate()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		response := helper.Response{
			Message: err.Error(),
		}
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	userID := uint64(r.Context().Value("user_id").(float64))
	notificationIDString := strings.TrimPrefix(r.URL.Path, "/request/action/")
	notificationID, err := strconv.ParseUint(notificationIDString, 10, 64)
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
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	request.UserID = userID
	request.NotificationID = notificationID

	serviceResponse, err := h.permissionService.RespondPermissionRequest(r.Context(), request)

	if err != nil {
		response := helper.Response{
			Message: err.Error(),
		}
		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResponse)
		return
	}

	response := helper.Response{
		Message: serviceResponse.Message,
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResponse)
}
