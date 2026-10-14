package evidence

import (
	"github.com/kentrasecurity/periscope/internal/policy"
	"strconv"
)

func Lookup(object any, path string) (any, bool) {
	parts, e := policy.Pointer(path)
	if e != nil {
		return nil, false
	}
	current := object
	for _, p := range parts {
		switch value := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = value[p]
			if !exists {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(p)
			if err != nil || index < 0 || index >= len(value) || strconv.Itoa(index) != p {
				return nil, false
			}
			current = value[index]
		default:
			return nil, false
		}
	}
	return current, true
}
