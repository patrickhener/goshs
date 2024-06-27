package httpserver

import (
	"io/fs"
	"strings"

	"github.com/patrickhener/goshs/logger"
)

func removeItem(sSlice []item, item string) []item {
	index := 0

	for idx, sliceItem := range sSlice {
		if item == sliceItem.Name {
			index = idx
		}
	}

	return append(sSlice[:index], sSlice[index+1:]...)
}

func (files *FileServer) PrintEmbeddedFiles() {
	err := fs.WalkDir(embedded, ".",
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				outPath := strings.TrimPrefix(path, "embedded")
				logger.Infof("Download embedded file at: %+v?embedded", outPath)
			}
			return nil
		})
	if err != nil {
		logger.Errorf("error printing info about embedded files: %+v", err)
	}

}
