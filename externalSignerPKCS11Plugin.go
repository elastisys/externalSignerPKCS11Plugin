package main

import (
	"crypto/rsa"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ThalesIgnite/crypto11"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	cfgPathLib  = "pathLib"
	cfgPIN      = "pin"
	cfgSlotID   = "slotId"
	cfgObjectID = "objectId"
)

var path, operation, pinFromConfig string
var slotID, objectID int

func certificate() error {
	config := &crypto11.Config{
		Path:              path,
		LoginNotSupported: true,
		SlotNumber:        &slotID,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return fmt.Errorf("crypto11 configure error: %v", err)
	}

	baObjectID := []byte{byte(objectID)}

	certDat, err := ctx.FindCertificate(baObjectID, nil, nil)
	if err != nil {
		return fmt.Errorf("find certificate error: %v", err)
	}
	// var certDat *x509.Certificate
	// ctx.ImportCertificate(baObjectID, certDat)
	if certDat == nil {
		return fmt.Errorf("certificate in slotID %v with objectID %v not found", slotID, objectID)
	}

	certificate := b64.StdEncoding.EncodeToString(certDat.Raw)

	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Certificate: %s\n", certificate)

	type Message struct {
		APIVersion  string `json:"apiVersion"`
		Kind        string `json:"kind"`
		Certificate string `json:"certificate"`
		// PublicKey   string `json:"publicKey"`
	}

	message := Message{
		APIVersion:  "external-signer.authentication.k8s.io/v1alpha1",
		Kind:        "ExternalPublicKey",
		Certificate: certificate,
		// PublicKey:   "pubkey",
	}

	b, err := json.Marshal(message)

	if err != nil {
		fmt.Errorf("marshal error: %v", err)
	}

	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Certificate: %s\n", certificate)

	fmt.Println(string(b))

	return nil
}

func sign(configMessageStr string) error {

	var pin string
	if pinFromConfig != "" {
		pin = pinFromConfig
	} else {
		fmt.Fprintf(os.Stderr, "[EXTERNAL] Enter pin: ")
		pinByte, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("pin error: %v", err)
		}
		fmt.Fprintf(os.Stderr, "\n")
		pin = string(pinByte)

		// reader := bufio.NewReader(os.Stdin)
		// fmt.Fprintf(os.Stderr, "Enter pin: ")
		// pinWithDelimiter, err := reader.ReadString('\n')
		// if err != nil {
		// 	fmt.Fprintf(os.Stderr, "Error when reading new pin: %v", err)
		// }
		// pin = strings.TrimSuffix(pinWithDelimiter, "\n")

		// fmt.Fprintf(os.Stderr, "New pin: [%s]\n", pin)
	}

	config := &crypto11.Config{
		Path:       path,
		Pin:        pin,
		SlotNumber: &slotID,
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return fmt.Errorf("crypto11 configure error: %v", err)
	}

	baObjectID := []byte{byte(objectID)}

	key, err := ctx.FindKeyPair(baObjectID, nil)
	if err != nil {
		return fmt.Errorf("find key pair rrror: %s", err)
	}
	if key == nil {
		return fmt.Errorf("private key in slotID with objectID not found")
	}

	type SignMessage struct {
		APIVersion     string `json:"apiVersion"`
		Kind           string `json:"kind"`
		Digest         string `json:"digest"`
		SignerOptsType string `json:"signerOptsType"`
		SignerOpts     string `json:"signerOpts"`
		// SignerOpts map[string]string `json:"signerOpts"`
	}

	var signMessage SignMessage

	err = json.Unmarshal([]byte(configMessageStr), &signMessage)
	if err != nil {
		return fmt.Errorf("unmarshal error: %v", err)
	}

	// fmt.Fprintf(os.Stderr, "[EXTERNAL] signMessage: %s\n", signMessage)

	digest, err := b64.StdEncoding.DecodeString(signMessage.Digest)
	if err != nil {
		return fmt.Errorf("digest decode error: %v", err)
	}

	var signature string

	switch signMessage.SignerOptsType {
	case "*rsa.PSSOptions":
		var pSSOptions rsa.PSSOptions

		fmt.Fprintf(os.Stderr, "[EXTERNAL] signMessage.SignerOpts: %s\n", signMessage.SignerOpts)
		err := json.Unmarshal([]byte(signMessage.SignerOpts), &pSSOptions)
		if err != nil {
			return fmt.Errorf("unmarshal error: %v", err)
		}

		// fmt.Fprintf(os.Stderr, "[EXTERNAL] pSSOptions: %d, %d\n", pSSOptions.Hash, pSSOptions.SaltLength)
		dat, err := key.Sign(nil, digest, &pSSOptions)
		if err != nil {
			return fmt.Errorf("sign error: %v", err)
		}
		signature = b64.StdEncoding.EncodeToString(dat)
	case "":
		return fmt.Errorf("SignerOpts type was not provided")
	default:
		return fmt.Errorf("SignerOpts for %s are not implemented", signMessage.SignerOptsType)
	}

	// pssOpts := &rsa.PSSOptions{
	// 	SaltLength: -1,
	// 	Hash:       crypto.SHA256.HashFunc(),
	// }

	// dat, err := key.Sign(nil, digest, pssOpts)
	// dat, err := key.Sign(nil, digest, signMessage.SignerOpts)
	// dat, err := key.Sign(nil, digest, opts)
	// signature := b64.StdEncoding.EncodeToString(dat)

	type Message struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Signature  string `json:"signature"`
	}

	message := Message{
		APIVersion: "external-signer.authentication.k8s.io/v1alpha1",
		Kind:       "ExternalSigner",
		Signature:  signature,
	}

	b, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Digest: %s\n", signMessage.Digest)
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Signature: %s\n", signature)

	fmt.Println(string(b))

	return nil
}

func parseConfig(configStr string) error {
	type ConfigMessage struct {
		APIVersion    string            `json:"apiVersion"`
		Kind          string            `json:"kind"`
		Configuration map[string]string `json:"configuration"`
	}

	var configMessage ConfigMessage

	err := json.Unmarshal([]byte(configStr), &configMessage)
	if err != nil {
		// fmt.Errorf("[EXTERNAL] exec: %v", err)
		return fmt.Errorf("unmarshal error: %v", err)
	}

	operation = configMessage.Kind
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Kind: %s\n", operation)
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] Pin from config file: %s\n", configMessage.Configuration[cfgPIN])
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] SlotID: %s\n", configMessage.Protocol.SlotID)
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] ObjectID: %s\n", configMessage.Protocol.ObjectID)

	path = configMessage.Configuration[cfgPathLib]
	if path == "" {
		return fmt.Errorf("must provide path %s", cfgPathLib)
	}

	pinFromConfig = configMessage.Configuration[cfgPIN]

	slotID, err = strconv.Atoi(configMessage.Configuration[cfgSlotID])
	if err != nil {
		return fmt.Errorf("must provide integer SlotID: %v", err)
	}

	objectID, err = strconv.Atoi(configMessage.Configuration[cfgObjectID])
	if err != nil {
		return fmt.Errorf("must provide integer ObjectID: %v", err)
	}

	return nil
}

func main() {

	// scanner := bufio.NewScanner(os.Stdin)
	// // for scanner.Scan() {
	// scanner.Scan()
	// configStr := scanner.Text()
	// fmt.Fprintf(os.Stderr, "[EXTERNAL] configStr: %s\n", configStr)
	// // }
	// if err := scanner.Err(); err != nil {
	// 	log.Println(err)
	// 	fmt.Fprintf(os.Stderr, "[EXTERNAL] %s\n", err)
	// }

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "[EXTERNAL] Argument missing\n")
		os.Exit(1)
	}

	configStr := os.Args[1]

	// fmt.Fprintf(os.Stderr, "[EXTERNAL] configStr: %s\n", configStr)

	err := parseConfig(configStr)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[EXTERNAL] Exit with failure: %v\n", err)
		os.Exit(1)
	}

	switch operation {
	case "Certificate":
		err = certificate()
	case "Sign":
		err = sign(configStr)
	default:
		err = fmt.Errorf("undefined operation %s", operation)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[EXTERNAL] Exit with failure: %v\n", err)
		os.Exit(1)
	}
}
