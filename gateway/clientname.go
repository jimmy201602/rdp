package gateway

import "unicode/utf16"

// targetClientName fits a client name into Client Core Data (at most 15
// UTF-16 units). Some clients, such as Windows App on macOS, fill all 16
// units without a terminator.
func targetClientName(s string) string {
	u := utf16.Encode([]rune(s))
	if len(u) <= 15 {
		return s
	}
	return string(utf16.Decode(u[:15]))
}
