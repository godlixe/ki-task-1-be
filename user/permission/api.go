package permission

import "errors"

type RequestPermissionRequest struct {
	UserID         uint64
	TargetUsername string
	FileID         uint64
}

type RequestPermissionResponse struct {
}

type RespondPermissionRequestRequest struct {
	UserID           uint64
	NotificationID   uint64
	PermissionStatus uint64 `json:"permission_status" binding:"required,oneof=accept reject"`
}

func (r *RespondPermissionRequestRequest) Validate() error {
	if r.PermissionStatus != 1 && r.PermissionStatus != 2 {
		return errors.New("Request invalid. Permission status value must be 1 or 2")
	}
	return nil
}

type RespondPermissionRequestResponse struct {
	Message string `json:"message"`
}
