package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

func ComputeHash(sources Sources) string {
	keys := make([]string, 0, len(sources))
	for k, v := range sources {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(sources[k])
	}
	h := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("sha256:%x", h)
}
