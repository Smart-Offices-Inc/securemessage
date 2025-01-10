package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"local/securemessages/internal/config"
)

type EncryptionService struct{}

func NewEncryptionService() *EncryptionService {
	return &EncryptionService{}
}

func (es *EncryptionService) GenerateAESKey() ([]byte, error) {
	logger := config.GetLogger()
	logger.Trace("Generating new AES key")

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		logger.WithError(err).Error("Failed to generate random bytes for AES key")
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	logger.Debug("AES key generated successfully")
	return key, nil
}

func (es *EncryptionService) EncryptWithMasterKey(plaintext []byte) ([]byte, error) {
	logger := config.GetLogger()
	logger.Trace("Encrypting data with Master Key")

	masterKey, err := config.GetSecureKey("master")
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve Master Key")
		return nil, err
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		logger.WithError(err).Error("Failed to create AES cipher block")
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.WithError(err).Error("Failed to create GCM")
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		logger.WithError(err).Error("Failed to generate nonce")
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	logger.Debug("Encryption with Master Key successful")
	return ciphertext, nil
}

func (es *EncryptionService) Encrypt(plaintext []byte) ([]byte, error) {
	logger := config.GetLogger()
	logger.WithField("plaintextLength", len(plaintext)).Trace("Encrypting data")

	aesKey, err := config.GetSecureKey("aes")
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve AES key")
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		logger.WithError(err).Error("Failed to create cipher block")
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.WithError(err).Error("Failed to create GCM")
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		logger.WithError(err).Error("Failed to generate nonce")
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	logger.WithField("ciphertextLength", len(ciphertext)).Debug("Encryption successful")
	return ciphertext, nil
}

func (es *EncryptionService) Decrypt(ciphertext []byte) ([]byte, error) {
	logger := config.GetLogger()
	logger.WithField("ciphertextLength", len(ciphertext)).Trace("Decrypting data")

	aesKey, err := config.GetSecureKey("aes")
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve AES key")
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		logger.WithError(err).Error("Failed to create cipher block")
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.WithError(err).Error("Failed to create GCM")
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		logger.Error("Ciphertext too short")
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to decrypt ciphertext")
		return nil, err
	}
	logger.Debug("Decryption successful")
	return plaintext, nil
}
