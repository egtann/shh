package main

// Design lifted from:
//
// https://github.com/mlesniak/go-keyz/blob/master/encryption.go

type encryptedData struct {
	data      []byte
	password  []byte
	nonceSize int
}

func encryptSymmetric(data []byte) (*encryptedData, error) {
	encData, err := rsa.EncryptOAEP(sha256.New(), randReader, key, message,
		nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return encData, nil
}

func encryptAsymmetric(password, pubkey []byte) ([]byte, error) {
	encryptedPass, err := rsa.EncryptOAEP(sha256.New(), randReader, key,
		message, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return encryptedPass, nil
}

func newRandomPassword(length int) ([]byte, error) {
	password := make([]byte, length)
	_, err := randReader.Read(password)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return password, nil
}
