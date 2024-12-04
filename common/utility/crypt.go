package utility

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/wit-id/blueprint-backend-go/toolkit/config"
	"golang.org/x/crypto/scrypt"
)

// GeneratePassword ...
func GeneratePassword(salt, password string) string {
	hash := sha1.New()
	_, _ = io.WriteString(hash, salt+password)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// GeneratePasswordSalt ...
func GeneratePasswordSalt(cfg config.KVStore) string {
	charset := cfg.GetString("salt.charset")
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, cfg.GetInt("salt.length"))

	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}

func GenerateSalt() string {
	salt := make([]byte, 16)
	rand.Read(salt)
	return base64.URLEncoding.EncodeToString(salt)
}

func HashPassword(password, salt string) string {
	saltedPassword := []byte(password + salt)
	hashedPassword, _ := scrypt.Key(saltedPassword, []byte(salt), 16384, 8, 1, 32)
	return base64.URLEncoding.EncodeToString(hashedPassword)
}
