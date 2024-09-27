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
