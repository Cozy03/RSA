package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func main() {

	prv_key, error := rsa.GenerateKey(rand.Reader, 2048)
	if error != nil {
		panic(error)
	}

	publicKey := prv_key.PublicKey

	modulusBytes := base64.StdEncoding.EncodeToString(prv_key.N.Bytes())
	privateExponentBytes := base64.StdEncoding.EncodeToString(prv_key.D.Bytes())
	fmt.Println(modulusBytes)
	fmt.Println(privateExponentBytes)
	fmt.Println(publicKey.E)

	encryptedBytes, error := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte("super secret message"),
		nil)
	if error != nil {
		panic(error)
	}

	fmt.Println("encrypted bytes: ", encryptedBytes)
	decryptedBytes, error := prv_key.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if error != nil {
		panic(error)
	}
	fmt.Println("decrypted message: ", string(decryptedBytes))

msg := []byte("verifiable message")

hashMsg := sha256.New()
_, error = hashMsg.Write(msg)
if error != nil {
	panic(error)
}
hashMsgSum := hashMsg.Sum(nil)


signature, error := rsa.SignPSS(rand.Reader, prv_key, crypto.SHA256, hashMsgSum, nil)
if error != nil {
	panic(error)
}

error = rsa.VerifyPSS(&publicKey, crypto.SHA256, hashMsgSum, signature, nil)
if error != nil {
	fmt.Println("could not verify signature: ", error)
	return
}

fmt.Println("signature verified")
}