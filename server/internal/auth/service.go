package auth

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrInactiveUser       = errors.New("user is inactive")
)

// Service provides authentication functionality
type Service struct {
	DB *gorm.DB
}

// NewService creates a new authentication service
func NewService(db *gorm.DB) *Service {
	return &Service{
		DB: db,
	}
}

// Claims represents JWT claims
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken generates a JWT token for a user
func (s *Service) GenerateToken(user *models.User) (string, error) {
	// Define the token expiration time (24 hours)
	expirationTime := time.Now().Add(24 * time.Hour)

	// Create the JWT claims
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "sentinel-server",
		},
	}

	// Create the token with signing method and claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Get the secret key from environment variable
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "default_secret_for_dev" // fallback for development
		log.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable for production.")
	}

	// Sign and return the token
	return token.SignedString([]byte(secret))
}

// ValidateToken validates a JWT token and returns the associated user
func (s *Service) ValidateToken(tokenString string) (*models.User, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (any, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the secret key from environment variable
		secret := os.Getenv("JWT_SECRET")
		if secret == "" {
			secret = "default_secret_for_dev" // fallback for development
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	// Validate the token and extract claims
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Find the user in the database
		var user models.User
		result := s.DB.Where("id = ? AND is_active = ?", claims.UserID, true).First(&user)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, result.Error
		}

		return &user, nil
	}

	return nil, errors.New("invalid token")
}

// AuthenticateUser authenticates a user with username and password
func (s *Service) AuthenticateUser(username, password string) (*models.User, error) {
	var user models.User

	// Find the user by username
	result := s.DB.Where("username = ? OR email = ?", username, username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, result.Error
	}

	// Check if the user is active
	if !user.IsActive {
		return nil, ErrInactiveUser
	}

	// Compare the provided password with the hashed password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return &user, nil
}

// CreateUser creates a new user account
func (s *Service) CreateUser(username, email, password, role string) (*models.User, error) {
	// Check if user already exists
	var existingUser models.User
	result := s.DB.Where("username = ? OR email = ?", username, email).First(&existingUser)
	if result.Error == nil {
		return nil, errors.New("user with this username or email already exists")
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, result.Error
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create the new user
	user := &models.User{
		Username: username,
		Email:    email,
		Password: string(hashedPassword),
		Role:     role,
		IsActive: true,
	}

	result = s.DB.Create(user)
	if result.Error != nil {
		return nil, result.Error
	}

	return user, nil
}

// ChangePassword allows a user to change their password
func (s *Service) ChangePassword(userID uint, oldPassword, newPassword string) error {
	var user models.User

	result := s.DB.First(&user, userID)
	if result.Error != nil {
		return result.Error
	}

	// Verify the old password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return ErrInvalidCredentials
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update the password
	user.Password = string(hashedNewPassword)
	result = s.DB.Save(&user)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// RefreshToken generates a new token with extended validity
func (s *Service) RefreshToken(tokenString string) (string, error) {
	user, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return s.GenerateToken(user)
}
