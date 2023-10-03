package file

// File represents a file entity
type File struct {
	ID     uint64 `json:"id"`
	UserID uint64 `json:"user_id"`

	Filename string `json:"filename"`
	Filepath string `json:"filepath"`

	// Metadata is an encrypted reference to
	// the file's key.
	Metadata []byte `json:"metadata"`
}
