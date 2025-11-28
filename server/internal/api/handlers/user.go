package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/0xA1M/sentinel-server/internal/auth"
	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// UserService handles user-related operations
type UserService struct {
	DB *gorm.DB
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{DB: db}
}

// GetUsersHandler returns all users
func GetUsersHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var users []models.User
		result := svc.DB.Where("is_active = ?", true).Find(&users)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve users", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)
	}
}

// GetUserHandler returns a specific user by ID
func GetUserHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		var user models.User
		result := svc.DB.First(&user, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

// CreateUserHandler creates a new user
func CreateUserHandler(svc *UserService, authSvc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Username == "" || req.Email == "" || req.Password == "" {
			http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
			return
		}

		// Validate role
		if req.Role != "admin" && req.Role != "user" {
			req.Role = "user"
		}

		// Create user
		user, err := authSvc.CreateUser(req.Username, req.Email, req.Password, req.Role)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Return user without password
		response := map[string]any{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// UpdateUserHandler updates an existing user
func UpdateUserHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		var req struct {
			Username *string `json:"username"`
			Email    *string `json:"email"`
			Role     *string `json:"role"`
			IsActive *bool   `json:"is_active"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var user models.User
		result := svc.DB.First(&user, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
			return
		}

		// Update user fields if provided
		if req.Username != nil {
			user.Username = *req.Username
		}
		if req.Email != nil {
			user.Email = *req.Email
		}
		if req.Role != nil {
			if *req.Role == "admin" || *req.Role == "user" {
				user.Role = *req.Role
			}
		}
		if req.IsActive != nil {
			user.IsActive = *req.IsActive
		}

		result = svc.DB.Save(&user)
		if result.Error != nil {
			http.Error(w, "Failed to update user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

// DeleteUserHandler deletes a user
func DeleteUserHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		var user models.User
		result := svc.DB.First(&user, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user", http.StatusInternalServerError)
			return
		}

		// Soft delete by setting is_active to false
		user.IsActive = false
		result = svc.DB.Save(&user)
		if result.Error != nil {
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// GetProfileHandler returns the authenticated user's profile
func GetProfileHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*models.User)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		// Return user profile without password
		response := map[string]any{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"role":       user.Role,
			"is_active":  user.IsActive,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// UpdateProfileHandler updates the authenticated user's profile
func UpdateProfileHandler(svc *UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*models.User)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		var req struct {
			Username *string `json:"username"`
			Email    *string `json:"email"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Update user fields if provided
		if req.Username != nil {
			user.Username = *req.Username
		}
		if req.Email != nil {
			user.Email = *req.Email
		}

		result := svc.DB.Save(&user)
		if result.Error != nil {
			http.Error(w, "Failed to update user profile", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

// ChangePasswordHandler allows a user to change their password
func ChangePasswordHandler(svc *UserService, authSvc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(auth.UserContextKey).(*models.User)
		if !ok {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		var req struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate old password
		err := authSvc.ChangePassword(user.ID, req.OldPassword, req.NewPassword)
		if err != nil {
			if err == auth.ErrInvalidCredentials {
				http.Error(w, "Invalid old password", http.StatusBadRequest)
			} else {
				http.Error(w, "Failed to change password", http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// LoginHandler handles user login
func LoginHandler(svc *UserService, authSvc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Authenticate user
		user, err := authSvc.AuthenticateUser(req.Username, req.Password)
		if err != nil {
			switch err {
			case auth.ErrInvalidCredentials:
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			case auth.ErrInactiveUser:
				http.Error(w, "User account is inactive", http.StatusForbidden)
			default:
				http.Error(w, "Authentication failed", http.StatusInternalServerError)
			}
			return
		}

		// Generate JWT token
		token, err := authSvc.GenerateToken(user)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Update last seen
		now := time.Now()
		user.LastSeen = &now
		svc.DB.Save(user)

		// Return token and user info
		response := map[string]any{
			"token": token,
			"user": map[string]any{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
				"role":     user.Role,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
