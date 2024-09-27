# Encryption

## Table of Contents

// ADJUST

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Usage](#usage)
4. [API Reference](#api-reference)
5. [Example](#example)
6. [Testing](#testing)
7. [Contributing](#contributing)
8. [License](#license)

## Introduction to AES, RC4, and DES

## Python

### Installation

Install pycrytodome within your system

```sh
pip install pycryptodome
```

### AES

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# initiate 16 byte key for aes and iv because we use CBC mode
key = get_random_bytes(16) 
iv = get_random_bytes(16)

# inititate encryptor
aes = AES.new(key, AES.MODE_CBC, iv)

plaintext = b'GedaGediGedaGedao'

# add padding to fullfil the block size
# encode to b64 for easier storing
ciphertext = b64encode(aes.encrypt(pad(plaintext, AES.block_size))).decode('utf-8')
print("Ciphertext:",ciphertext)

# initiate decryptor
aes = AES.new(key, AES.MODE_CBC, iv)

# decrypt the ciphertext
plaintext = unpad(aes.decrypt(b64decode(ciphertext)), AES.block_size).decode('utf-8')
print("Plaintext: ",plaintext)
```


### RC4

### DES

```python
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# inititate DES key and IV because we use CBC mode
key = get_random_bytes(8)
iv = get_random_bytes(8)

# initialize encryptor
cipher = DES.new(key, DES.MODE_CBC, iv)

# add padding to fullfil the block size
plaintext = b"GedaGediGedaGedao"
ciphertext = b64encode(cipher.encrypt(pad(plaintext, DES.block_size))).decode('utf-8')

print(f"Ciphertext: {ciphertext}")

# initialize decryptor
cipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_data = unpad(cipher.decrypt(b64decode(ciphertext)), DES.block_size).decode('utf-8')

print(f"Plaintext: {decrypted_data}")
```

## Golang
In go, we can implement various cryptographic operation using `crypto` package. This package is part of go standard library, hence no additional installation needed. Official documentation for this package can be read here: https://pkg.go.dev/crypto.

### AES

#### Package aes
To implement aes encryption in golang, we can use `crypto/aes` package. On those package, there is a `NewCipher` function to create a `aes cipher` instance. This function received a key which can be 16, 32, or 64 bytes to select AES-128, AES-192, or AES-256. Key other than those will produce an error.
```go
func NewCipher(key []byte) (cipher.Block, error){}
```
We also need `crypto/cipher` package to implement block cipher mode on AES. More complete information and the official source code can be read in https://pkg.go.dev/crypto/aes and https://pkg.go.dev/crypto/cipher.

#### Source Code
First, we need to create `encrypt` and `decrypt` function which receive data (plaintext/ciphertext) and key as an array of byte. These function then return an array of byte represent `ciphertext` for `encrypt` and `plaintext` for `decrypt`.
```go
func aesCbcEncrypt(plaintext, key []byte) ([]byte, error) {
	// Check if the plaintext size is not a multiple of the AES block size (16 bytes)
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	// Create an instance of the AES cipher using the provided key
	// The key size determines the security level (AES-128, AES-192, AES-256)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Prepare the ciphertext by allocating a byte slice to store both the IV and the encrypted data
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	// Generate a random IV using a cryptographically secure random number generator
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Encrypt the plaintext using CBC mode (Cipher Block Chaining).
	// CBC mode requires the IV for chaining blocks of ciphertext.
	// The actual ciphertext will start after the IV in the ciphertext slice (i.e., at aes.BlockSize).
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func aesCbcDecrypt(ciphertext, key []byte) ([]byte, error) {
	// Create an instance of the AES cipher using the provided key
	// The key size determines the security level (AES-128, AES-192, AES-256)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}

	// Extract the Initialization Vector (IV) from the first 16 bytes of the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Check if the remaining ciphertext (after the IV) is a multiple of the AES block size.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	// Initialize the AES CBC decryption mode using the block cipher and the IV.
	mode := cipher.NewCBCDecrypter(block, iv)

	// Perform the decryption of the ciphertext into the plaintext.
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
```

As AES is a block cipher, we need `Pad()` functions to ensure the plaintext is a multiple of 16 bytes, which is the block size for AES, by add a padding. We also need `Unpad()` function to remove the padding.
```go
func Pad(input []byte, blockSize int) []byte {
	r := len(input) % blockSize
	pl := blockSize - r
	for i := 0; i < pl; i++ {
		input = append(input, byte(pl))
	}
	return input
}

func Unpad(input []byte) ([]byte, error) {
	if input == nil || len(input) == 0 {
		return nil, nil
	}

	pc := input[len(input)-1]
	pl := int(pc)

	if len(input) < pl {
		return nil, errors.New("invalid padding")
	}
	p := input[len(input)-(pl):]
	for _, pc := range p {
		if uint(pc) != uint(len(p)) {
			return nil, errors.New("invalid padding")
		}
	}

	return input[:len(input)-pl], nil
}
```

Now, we can implement aes encryption using CBC mode utilizing the `aesCbcEncrypt()` and `aesCbcDecrypt()` functions.
```go
// initiate secret key
key := make([]byte, 16) // AES-128
// key := make([]byte, 32) // AES-192
// key := make([]byte, 64)	// AES-256
_, err := io.ReadFull(rand.Reader, key)
if err != nil {
  log.Fatal(err)
}

// initialize data we want to encrypt
plaintext := []byte("abcdefgh12345678asdlkasjn")
// we can also encrypt a file
// plaintext, err = os.ReadFile("./tes.txt")
// if err != nil {
// 	log.Fatal(err)
// }
pad_plaintext := Pad(plaintext, 16)

ciphertext, err := aesCbcEncrypt(pad_plaintext, key)
if err != nil {
  log.Fatal(err)
}

pad_decrypt, err := aesCbcDecrypt(ciphertext, key)
if err != nil {
  log.Fatal(err)
}

decrypt, err := Unpad(pad_decrypt)
if err != nil {
  log.Fatal(err)
}

fmt.Printf("AES\n")
fmt.Printf("Plaintext: %s\n", string(plaintext))
fmt.Printf("Ciphertext: %s\n", string(ciphertext))
fmt.Printf("Decrypted Ciphertext: %s\n", string(decrypt))
```
For other block modes, you can use this function provided in the `crypto/cipher` package:
- CFB: `NewCFBDecrypter` and `NewCFBEncrypter`
- CTR: `NewCTR`
- GCM: `NewGCM`

### RC4

#### Package rc4
To implement rc4 encryption in golang, we can use `crypto/rc4` package. On those package, there is a `Cipher` struct along with `NewCipher` method. There is also function `NewCipher` to create a `rc4 cipher` instance. More complete information and the official source code can be read in https://pkg.go.dev/crypto/rc4.
```R
type Cipher struct {
	// contains filtered or unexported fields
}

func NewCipher(key []byte) (*Cipher, error){}

func (c *Cipher) XORKeyStream(dst, src []byte){}
```

#### Source Code
First, we need to create `encrypt` and `decrypt` function which receive data (plaintext/ciphertext) and key as an array of byte. These function then return an array of byte represent `ciphertext` for `encrypt` and `plaintext` for `decrypt`.

```go
func rc4Encrypt(plaintext, key []byte) ([]byte, error) {
  // create instance of rc4 cipher
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

  // initialize ciphertext with same size
	ciphertext := make([]byte, len(plaintext))

  // execute XORKeyStream to encrypt plaintext
	c.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

func rc4Decrypt(ciphertext, key []byte) ([]byte, error) {
  // create instance of rc4 cipher
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

  // initialize plaintext with same size
	plaintext := make([]byte, len(ciphertext))

  // execute XORKeyStream to decrypt ciphertext
	c.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
```

Now, we can implement rc4 encryption utilizing the `rc4Encrypt()` and `rc4Decrypt()` functions.
```go
func main() {
	// create random key
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		log.Fatal(err)
	}

	// initialize data we want to encrypt
	plaintext := []byte("halo dunia") // string data
	// we can also encrypt a file
	// plaintext, err = os.ReadFile("./tes.txt")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// encrypt data
	ciphertext, err := rc4Encrypt(plaintext, key)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt ciphertext
	decrypted, err := rc4Decrypt(ciphertext, key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Plaintext: %s\n", string(plaintext))
	fmt.Printf("Ciphertext: %s\n", string(ciphertext))
	fmt.Printf("Decrypted Ciphertext: %s\n", string(decrypted))
}
```

### DES

## JavaScript

### AES

### RC4

### DES

#### Installation

To get started, install the library that will be needed. We will need Crypto and Crypto-js for DES.

#### Source code

Firstly, provide safely generated key with `crypto` library function `randomBytes()`. After the key obtained, safely encrypt the words and decrypt it when needed.

```js
const CryptoJS = require("crypto-js");
const crypto = require("crypto");

// Generate a secure random 64-bit key (8 bytes) for DES key
const generateKey = () => {
  const key = crypto.randomBytes(8); // 8 bytes = 64 bits
  return key.toString("hex"); // Convert to hex string for easy representation
};

const key = generateKey();

// Encrypt words with generated key
var encrypted = CryptoJS.DES.encrypt("Hello World", key);
// Decrypt the encrypted words with the same key
var decrypted = CryptoJS.DES.decrypt(encrypted, key);

console.log("Encrypted:", encrypted.toString());
// Output = Encrypted: <random encrypted string>
console.log("Decrypted:", decrypted.toString(CryptoJS.enc.Utf8));
// Output = Encrypted: Hello World
```

For further information, you can access
https://cryptojs.gitbook.io/docs

## PHP

### AES

#### Source Code

In order to encrypt/decrypt things in php, there is a library that provide encryption method like AES. For this example, AES 256 CBC (Cipher Block Chaining) will be used

```php
<?php
// Define cipher
$cipher = "aes-256-cbc";

// Generate a 256-bit encryption key
$encryption_key = openssl_random_pseudo_bytes(32);

// Generate an initialization vector
$iv_size = openssl_cipher_iv_length($cipher);
$iv = openssl_random_pseudo_bytes($iv_size);

// Data to encrypt
$data = "Hello World";
$encrypted_data = openssl_encrypt($data, $cipher, $encryption_key, 0, $iv);

// Display encrypted text
echo "Encrypted Text: " . $encrypted_data . "\n";

// Decrypt data
$decrypted_data = openssl_decrypt($encrypted_data, $cipher, $encryption_key, 0, $iv);

// Display decrypted text
echo "Decrypted Text: " . $decrypted_data . "\n";
?>
```

Encryption key is a secret value used to do encryption and decryption, while the IV or Initialization Vector is a random or pseudo-random value used with the key to ensure that same plaintext won't have same ciphertext everytime it produced.
Resource,
https://www.phpcluster.com/aes-encryption-and-decryption-in-php/
