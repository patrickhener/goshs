package httpserver

func removeItem(sSlice []item, item string) []item {
	index := 0

	for idx, sliceItem := range sSlice {
		if item == sliceItem.Name {
			index = idx
		}
	}

	return append(sSlice[:index], sSlice[index+1:]...)
}
