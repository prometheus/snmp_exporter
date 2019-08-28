# cryptotool

Run make to build the binary

```sh
make
go build -v ./...
```

This is a tool to encrypt (and decrypt) your community string with a passphrase. (In this implementation, the sha256 hash of your passphrase is used for the 32byte key needed for AES)

To encrypt your community of 'public' with the passphrase 'password'

```sh
./cryptotool encryptAesGcm password public
Xj3Ag6RZwwSm5PiBoongcPnxCb3q7yLe9Ptcfi7JZCMQNA==
```

Test the decryption with the same tool

```sh
./cryptotool decryptAesGcm password Xj3Ag6RZwwSm5PiBoongcPnxCb3q7yLe9Ptcfi7JZCMQNA==
public
```

AES GCM is used instead of AES CFB due to the ability to have a random initial 
vector. This means each ciphertext generated is unique even with the same passphrase 
and community string. If you have multiple devices with the same community, you
should generate multiple encrypted community strings. This way, no one will
know that multiple devices have the same community string.
