package scripts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptWithMasterKey(key []byte, masterKey []byte) (string, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, key, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func main() {
	masterKey := "YOUR_MASTER_KEY_BASE64" // Replace with your base64 master key
	decodedMasterKey, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil || len(decodedMasterKey) != 32 {
		log.Fatalf("Invalid master key: %v", err)
	}

	aesKey, err := generateAESKey()
	if err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}

	encryptedAESKey, err := encryptWithMasterKey(aesKey, decodedMasterKey)
	if err != nil {
		log.Fatalf("Failed to encrypt AES key: %v", err)
	}

	fmt.Printf("Generated AES Key (Base64): %s\n", base64.StdEncoding.EncodeToString(aesKey))
	fmt.Printf("Encrypted AES Key (Base64): %s\n", encryptedAESKey)
}
