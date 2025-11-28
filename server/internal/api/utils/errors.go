package utils

import (
	"encoding/json"
	"net/http"
)

// APIError represents an API error
type APIError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// Error implements the error interface
func (e *APIError) Error() string {
	return e.Message
}

// NewAPIError creates a new API error
func NewAPIError(message string, status int) *APIError {
	return &APIError{
		Status:  status,
		Message: message,
	}
}

// SendErrorResponse sends an error response
func SendErrorResponse(w http.ResponseWriter, err *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "error",
		"message": err.Message,
	})
}

// SendSuccessResponse sends a success response
func SendSuccessResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"data":   data,
	})
}

// SendSuccessResponseWithMessage sends a success response with a message
func SendSuccessResponseWithMessage(w http.ResponseWriter, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": message,
		"data":    data,
	})
}