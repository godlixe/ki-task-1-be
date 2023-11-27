package file

import (
	"errors"
	"os"
)

type fileSystem struct {
}

func NewFileSystem() *fileSystem {
	return &fileSystem{}
}

func (fs *fileSystem) Read(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (fs *fileSystem) Write(path string, data []byte) error {
	err := os.WriteFile(path, data, 0644)
	return err
}

func (fs *fileSystem) NewDir(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			return err
		}

		return nil
	}

	return errors.New("directory exists")
}
