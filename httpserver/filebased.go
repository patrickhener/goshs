package httpserver

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func (fs *FileServer) findSpecialFile(fis []fs.FileInfo, file *os.File) (configFile, error) {
	var config configFile

	for _, fi := range fis {
		if fi.Name() == ".goshs" {
			openFile := filepath.Join(file.Name(), fi.Name())

			configFileDisk, err := os.Open(openFile)
			if err != nil {
				return config, err
			}

			configFileBytes, err := io.ReadAll(configFileDisk)
			if err != nil {
				return config, err
			}

			if err := json.Unmarshal(configFileBytes, &config); err != nil {
				return config, err
			}

			return config, nil
		}
	}

	return config, nil
}
