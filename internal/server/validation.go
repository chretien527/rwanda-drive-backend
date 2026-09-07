package server

import (
	"net/mail"
	"regexp"
	"strings"
)

// ValidateEmail checks if an email address is structurally valid
func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

// ValidatePhoneRW validates Rwanda phone numbers (local and international formats)
// Accepts: +250XXXXXXXXX, 07XXXXXXXX, 08XXXXXXXX
var rwPhoneRegex = regexp.MustCompile(`^(\+250|250)?(7[0-9]{8}|8[0-9]{8})$`)

func ValidatePhoneRW(phone string) bool {
	if phone == "" {
		return true // Phone is optional for some flows
	}
	normalized := strings.ReplaceAll(phone, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	return rwPhoneRegex.MatchString(normalized)
}

// ValidatePassword enforces minimum password strength
func ValidatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "password must be at least 8 characters"
	}
	if len(password) > 128 {
		return false, "password must be at most 128 characters"
	}
	return true, ""
}

// ValidateRole checks if a role string is a valid application role
func ValidateRole(role string) bool {
	switch role {
	case "DRIVER", "OFFICER", "ADMIN", "SUPER_ADMIN":
		return true
	default:
		return false
	}
}
