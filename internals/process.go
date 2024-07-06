package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PadKey ensures the key is of a valid length for AES (16, 24, or 32 bytes)
func PadKey(key *string) {
	keyLen := len(*key)
	if keyLen < 16 {
		*key = *key + strings.Repeat("0", 16-keyLen)
	} else if keyLen < 24 {
		*key = *key + strings.Repeat("0", 24-keyLen)
	} else if keyLen < 32 {
		*key = *key + strings.Repeat("0", 32-keyLen)
	} else if keyLen > 32 {
		*key = (*key)[:32]
	}
}

// ProcessFile encrypts or decrypts the given file based on the provided flags
func ProcessFile(key []byte, encrypt bool, deleteOriginal bool, filePath string, wg *sync.WaitGroup) {
	defer wg.Done()

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating cipher block:", err)
		return
	}

	if encrypt {
		fmt.Printf("Encrypting file: %s\n", filePath)
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Println("Error creating GCM:", err)
			return
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Println("Error reading nonce:", err)
			return
		}

		fileInfo, err := file.Stat()
		if err != nil {
			fmt.Println("Error stating file:", err)
			return
		}

		fileData := make([]byte, fileInfo.Size())
		file.Read(fileData)

		encryptedData := gcm.Seal(nil, nonce, fileData, nil)

		encryptedFilePath := filePath + ".enc"
		encryptedFile, err := os.Create(encryptedFilePath)
		if err != nil {
			fmt.Println("Error creating encrypted file:", err)
			return
		}
		defer encryptedFile.Close()

		encryptedFile.Write(nonce)
		encryptedFile.Write(encryptedData)

		fmt.Printf("File encrypted and saved as %s\n", encryptedFilePath)

		if deleteOriginal {
			err := os.Remove(filePath)
			if err != nil {
				fmt.Println("Error deleting original file:", err)
			} else {
				fmt.Printf("Original file %s deleted\n", filePath)
			}
		}
	} else {
		fmt.Printf("Decrypting file: %s\n", filePath)
		fileInfo, err := file.Stat()
		if err != nil {
			fmt.Println("Error stating file:", err)
			return
		}

		fileData := make([]byte, fileInfo.Size())
		file.Read(fileData)

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Println("Error creating GCM:", err)
			return
		}

		nonceSize := gcm.NonceSize()
		nonce := fileData[:nonceSize]
		encryptedData := fileData[nonceSize:]

		decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			fmt.Println("Error decrypting file:", err)
			return
		}

		decryptedFilePath := strings.TrimSuffix(filePath, ".enc")
		decryptedFile, err := os.Create(decryptedFilePath)
		if err != nil {
			fmt.Println("Error creating decrypted file:", err)
			return
		}
		defer decryptedFile.Close()

		decryptedFile.Write(decryptedData)

		fmt.Printf("File decrypted and saved as %s\n", decryptedFilePath)

		err = os.Remove(filePath)
		if err != nil {
			fmt.Println("Error deleting encrypted file:", err)
		} else {
			fmt.Printf("Encrypted file %s deleted\n", filePath)
		}
	}
}

// ProcessDirectory recursively processes all files in the given directory
func ProcessDirectory(key []byte, encrypt bool, deleteOriginal bool, directoryPath string) {
	var wg sync.WaitGroup

	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			wg.Add(1)
			go ProcessFile(key, encrypt, deleteOriginal, path, &wg)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking the directory:", err)
		return
	}

	wg.Wait()
}

func main() {
	// Define the command line flags
	key := flag.String("key", "", "the encryption key")
	encrypt := flag.Bool("encrypt", false, "encrypt a file or directory")
	decrypt := flag.Bool("decrypt", false, "decrypt a file or directory")
	deleteOriginal := flag.Bool("d", true, "delete the original file after encryption")
	flag.Parse()

	// Check if the key was provided
	if *key == "" {
		fmt.Println("Error: encryption key must be provided")
		os.Exit(1)
	}

	// Pad or trim the key to a valid length for AES
	PadKey(key)
	fmt.Printf("Using key: %s\n", *key)

	// Check if either encrypt or decrypt was specified
	if !*encrypt && !*decrypt {
		fmt.Println("Error: either -encrypt or -decrypt must be specified")
		os.Exit(1)
	}

	// Check if both encrypt and decrypt were specified
	if *encrypt && *decrypt {
		fmt.Println("Error: cannot specify both -encrypt and -decrypt")
		os.Exit(1)
	}

	// Get the path to the file or directory
	path := flag.Arg(0)
	if path == "" {
		fmt.Println("Error: file or directory path must be provided")
		os.Exit(1)
	}

	// Process the file or directory
	if *encrypt {
		fileInfo, err := os.Stat(path)
		if err != nil {
			fmt.Println("Error stating file or directory:", err)
			os.Exit(1)
		}

		if fileInfo.IsDir() {
			ProcessDirectory([]byte(*key), true, *deleteOriginal, path)
		} else {
			var wg sync.WaitGroup
			wg.Add(1)
			go ProcessFile([]byte(*key), true, *deleteOriginal, path, &wg)
			wg.Wait()
		}
	} else if *decrypt {
		fileInfo, err := os.Stat(path)
		if err != nil {
			fmt.Println("Error stating file or directory:", err)
			os.Exit(1)
		}

		if fileInfo.IsDir() {
			ProcessDirectory([]byte(*key), false, false, path)
		} else {
			var wg sync.WaitGroup
			wg.Add(1)
			go ProcessFile([]byte(*key), false, false, path, &wg)
			wg.Wait()
		}
	}
}
