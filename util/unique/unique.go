package unique

func StringSlice(input []string) []string {
	unique := make(map[string]struct{})
	for _, str := range input {
		unique[str] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for str := range unique {
		result = append(result, str)
	}

	return result
}
