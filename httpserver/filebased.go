package httpserver

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
)

func (fs *FileServer) findSpecialFile(fis []fs.FileInfo) (bool, configFile, error) {
	var config configFile
	for _, fi := range fis {
		if fi.Name() == ".goshs" {
			configFileDisk, err := os.Open(".goshs")
			if err != nil {
				return false, config, err
			}
			configFileBytes, err := io.ReadAll(configFileDisk)
			if err != nil {
				return false, config, err
			}

			if err := json.Unmarshal(configFileBytes, &config); err != nil {
				return false, config, err
			}

			return true, config, nil
		}
	}
	return false, config, nil
}
