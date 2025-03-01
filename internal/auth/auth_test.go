package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	// Test a header that does not contain a space
	headers := http.Header{}
	headers.Set("Authorization", "InvalidValue")
	_, err := GetAPIKey(headers)
	expectedError := "malformed authorization header"
	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected error %q, got %v", expectedError, err)
	}

	// Test a header with the wrong prefix
	headers.Set("Authorization", "Bearer sometoken")
	_, err = GetAPIKey(headers)
	if err == nil || err.Error() != expectedError {
		t.Errorf("Expected error %q, got %v", expectedError, err)
	}
}

func TestGetAPIKey_ValidAuthHeader(t *testing.T) {
	expectedAPIKey := "my-secret-key"
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey "+expectedAPIKey)
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if apiKey != expectedAPIKey {
		t.Errorf("Expected API key %q, got %q", expectedAPIKey, apiKey)
	}
}

// Optional: Test a header with extra fields
func TestGetAPIKey_ValidAuthHeaderWithExtraFields(t *testing.T) {
	expectedAPIKey := "my-secret-key"
	// Even if there are extra words, the function should return the second word.
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey "+expectedAPIKey+" extra-data")
	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if apiKey != expectedAPIKey {
		t.Errorf("Expected API key %q, got %q", expectedAPIKey, apiKey)
	}
}
