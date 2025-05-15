package logger

import (
	"fmt"
	"testing"
)

func TestIsBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		// Valid Base64 strings
		{"SGVsbG8gd29ybGQ=", true}, // "Hello world"
		{"U29tZSB0ZXh0", true},     // "Some text" (no padding)
		{"U29tZSB0ZXh0Cg==", true}, // "Some text\n"

		// Invalid Base64 strings
		{"NotBase64!", false},
		{"12345", false},            // Invalid length
		{"SGVsbG8===", false},       // Invalid padding
		{"SGVsbG8#d29ybGQ=", false}, // Invalid character

		// Edge cases
		{"", true},      // Empty string is valid Base64 here
		{"====", false}, // Only padding
	}

	for _, tt := range tests {
		result := isBase64(tt.input)
		if result != tt.expected {
			t.Errorf("isBase64(%q) = %v; want %v", tt.input, result, tt.expected)
		}
	}
}

func TestValidateAndParseJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantOK   bool
		wantType string
	}{
		{
			name:     "valid object",
			input:    []byte(`{"key": "value"}`),
			wantOK:   true,
			wantType: "map[string]interface {}",
		},
		{
			name:     "valid array",
			input:    []byte(`[1, 2, 3]`),
			wantOK:   true,
			wantType: "[]interface {}",
		},
		{
			name:     "valid string",
			input:    []byte(`"hello"`),
			wantOK:   true,
			wantType: "string",
		},
		{
			name:     "valid number",
			input:    []byte(`123.45`),
			wantOK:   true,
			wantType: "float64",
		},
		{
			name:     "valid bool",
			input:    []byte(`true`),
			wantOK:   true,
			wantType: "bool",
		},
		{
			name:     "valid null",
			input:    []byte(`null`),
			wantOK:   true,
			wantType: "<nil>",
		},
		{
			name:     "invalid JSON",
			input:    []byte(`{key: value}`),
			wantOK:   false,
			wantType: "",
		},
		{
			name:     "empty input",
			input:    []byte(``),
			wantOK:   false,
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, result := validateAndParseJSON(tt.input)

			if ok != tt.wantOK {
				t.Errorf("expected ok=%v, got %v", tt.wantOK, ok)
			}

			if ok && tt.wantType != "" {
				actualType := typeOf(result)
				if actualType != tt.wantType {
					t.Errorf("expected type=%v, got %v", tt.wantType, actualType)
				}
			}
		})
	}
}

// helper function to get type as string
func typeOf(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", v)
}
