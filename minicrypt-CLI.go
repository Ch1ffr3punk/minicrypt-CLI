package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"filippo.io/edwards25519"
)

const (
	maxMessageSize    = 4096 * 1024
	signatureMarker   = "----Ed25519 Signature----"
	uint64Bytes       = 8
	privateKeyFilename = "private.pem"
	publicKeyFilename    = "public.pem"
	defaultPadding    = 4096
	separator         = "\n=== MINICRYPT PADDING SEPARATOR ===\n"
	sizePrefix        = "PADDING_SIZE:"
	paddingChars      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	padSize int
	domain  = createDomain()
	rng     = mrand.New(mrand.NewSource(time.Now().UnixNano()))
)

func init() {
	flag.IntVar(&padSize, "p", defaultPadding, "Padding size")
}

func createDomain() []byte {
	r := []byte{}
	for i := 'A'; i <= 'Z'; i++ {
		r = append(r, byte(i))
	}
	return r
}

func secureTempFile() (*os.File, error) {
	return os.CreateTemp("", "minicrypt-tmp-")
}

func cleanupTempFile(f *os.File) {
	if f == nil {
		return
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		log.Printf("Error removing temporary file: %v", err)
	}
}

func savePEM(filename string, data *memguard.LockedBuffer, pemType string) error {
	block := &pem.Block{
		Type:  pemType,
		Bytes: data.Bytes(),
	}
	return os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

func loadPEM(filename string) (*memguard.LockedBuffer, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM decoding failed")
	}
	return memguard.NewBufferFromBytes(block.Bytes), nil
}

func loadPrivateKey(specificPath string) (*memguard.LockedBuffer, error) {
	keyFilePath := specificPath
	if keyFilePath == "" {
		keyFilePath = privateKeyFilename
	}
	return loadPEM(keyFilePath)
}

func validatePublicKey(pk *memguard.LockedBuffer) error {
	_, err := new(edwards25519.Point).SetBytes(pk.Bytes())
	return err
}

func loadPublicKey(name string, specificPath string) (*memguard.LockedBuffer, error) {
	var keyPath string
	if specificPath != "" {
		keyPath = specificPath
	} else {
		keyPath = name + ".pem"
	}

	buf, err := loadPEM(keyPath)
	if err != nil {
		return nil, err
	}

	if err := validatePublicKey(buf); err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("invalid public key: %v", err)
	}
	return buf, nil
}

func ed25519PrivateKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	h := sha512.New()
	h.Write(pk.Bytes()[:32])
	out := h.Sum(nil)
	return memguard.NewBufferFromBytes(out[:curve25519.ScalarSize]), nil
}

func ed25519PublicKeyToCurve25519(pk *memguard.LockedBuffer) (*memguard.LockedBuffer, error) {
	p, err := new(edwards25519.Point).SetBytes(pk.Bytes())
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %v", err)
	}
	return memguard.NewBufferFromBytes(p.BytesMontgomery()), nil
}

func generateKeyPair() (*memguard.LockedBuffer, *memguard.LockedBuffer, error) {
	var priv []byte
	var pub []byte
	var err error

	for {
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		_, err = new(edwards25519.Point).SetBytes(pub)
		if err == nil {
			break
		}
	}

	return memguard.NewBufferFromBytes(priv), memguard.NewBufferFromBytes(pub), nil
}

func encrypt(pubKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	curvePub, err := ed25519PublicKeyToCurve25519(pubKey)
	if err != nil {
		return fmt.Errorf("invalid public key for encryption: %v", err)
	}
	defer curvePub.Destroy()

	ephPriv, ephPub, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key pair: %v", err)
	}
	defer ephPriv.Destroy()
	defer ephPub.Destroy()

	curveEphPriv, err := ed25519PrivateKeyToCurve25519(ephPriv)
	if err != nil {
		return fmt.Errorf("failed to convert ephemeral private key: %v", err)
	}
	defer curveEphPriv.Destroy()

	curveEphPub, err := ed25519PublicKeyToCurve25519(ephPub)
	if err != nil {
		return fmt.Errorf("failed to convert ephemeral public key: %v", err)
	}
	defer curveEphPub.Destroy()

	sharedSecret, err := curve25519.X25519(curveEphPriv.Bytes(), curvePub.Bytes())
	if err != nil {
		return fmt.Errorf("key exchange failed: %v", err)
	}
	secureSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSecret.Destroy()

	aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %v", err)
	}

	nonce := memguard.NewBuffer(aead.NonceSize())
	defer nonce.Destroy()
	if _, err := rand.Read(nonce.Bytes()); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	secureData := memguard.NewBufferFromBytes(data)
	defer secureData.Destroy()

	ciphertext := aead.Seal(nil, nonce.Bytes(), secureData.Bytes(), nil)
	output := memguard.NewBuffer(len(curveEphPub.Bytes()) + len(nonce.Bytes()) + len(ciphertext))
	defer output.Destroy()

	copy(output.Bytes(), curveEphPub.Bytes())
	copy(output.Bytes()[len(curveEphPub.Bytes()):], nonce.Bytes())
	copy(output.Bytes()[len(curveEphPub.Bytes())+len(nonce.Bytes()):], ciphertext)

	encoded := base64.StdEncoding.EncodeToString(output.Bytes())
	_, err = fmt.Fprintln(w, chunk64(encoded))
	return err
}

func decrypt(privKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read input: %v", err)
	}

	if bytes.Contains(data, []byte(signatureMarker)) {
		parts := bytes.Split(data, []byte(signatureMarker))
		if len(parts) < 1 {
			return errors.New("invalid signed message format")
		}
		data = bytes.TrimSpace(parts[0])
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return fmt.Errorf("base64 decoding failed: %v", err)
	}
	if len(decoded) < 56 {
		return errors.New("message too short to be valid")
	}

	secureDecoded := memguard.NewBufferFromBytes(decoded)
	defer secureDecoded.Destroy()

	curvePriv, err := ed25519PrivateKeyToCurve25519(privKey)
	if err != nil {
		return fmt.Errorf("private key conversion failed: %v", err)
	}
	defer curvePriv.Destroy()

	ephPub := secureDecoded.Bytes()[:32]
	nonce := secureDecoded.Bytes()[32:56]
	ciphertext := secureDecoded.Bytes()[56:]

	var sharedSecret []byte
	maxRetries := 2
	for i := 0; i < maxRetries; i++ {
		sharedSecret, err = curve25519.X25519(curvePriv.Bytes(), ephPub)
		if err == nil {
			break
		}
		if i == maxRetries-1 {
			return fmt.Errorf("key exchange failed after %d attempts: %v", maxRetries, err)
		}
	}

	secureSecret := memguard.NewBufferFromBytes(sharedSecret)
	defer secureSecret.Destroy()

	aead, err := chacha20poly1305.NewX(secureSecret.Bytes())
	if err != nil {
		return fmt.Errorf("failed to initialize decryption: %v", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write output: %v", err)
	}

	return nil
}

func signMessage(privKey *memguard.LockedBuffer, r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\r"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	data = bytes.TrimSuffix(data, []byte("\r\n"))

	signature := ed25519.Sign(privKey.Bytes(), data)
	signatureHex := hex.EncodeToString(signature)
	pubKey := ed25519.PrivateKey(privKey.Bytes()).Public().(ed25519.PublicKey)
	pubKeyHex := hex.EncodeToString(pubKey)

	fmt.Fprintf(w, "%s\r\n%s\r\n%s\r\n%s\r\n%s\r\n",
		string(data),
		signatureMarker,
		signatureHex[:64],
		signatureHex[64:],
		pubKeyHex)
	return nil
}

func verifyMessage(r io.Reader, w io.Writer) error {
	var data []byte
	var sigHex, pubKeyHex string
	inSig := false

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == signatureMarker {
			inSig = true
			continue
		}
		if inSig {
			if sigHex == "" {
				sigHex = line
			} else if len(sigHex) == 64 {
				sigHex += line
			} else {
				pubKeyHex = line
				break
			}
		} else {
			data = append(data, scanner.Bytes()...)
			data = append(data, '\r', '\n')
		}
	}

	data = bytes.TrimSuffix(data, []byte("\r\n"))
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}

	if ed25519.Verify(pubKey, data, signature) {
		fmt.Fprintln(w, string(data))
		fmt.Fprintln(w, "Signature is valid.")
	} else {
		fmt.Fprintln(w, "Signature is not valid.")
	}
	return nil
}

func pad(r io.Reader, size int, w io.Writer) error {
	original, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read error: %v", err)
	}

	metadataSize := len(separator) + len(sizePrefix) + 12
	if size < len(original)+metadataSize {
		return fmt.Errorf("target size %d too small for content (minimum %d)",
			size, len(original)+metadataSize)
	}
	paddingNeeded := size - len(original) - metadataSize

	padding := strings.Repeat(paddingChars, paddingNeeded/len(paddingChars)+1)[:paddingNeeded]

	sizeMarker := sizePrefix + base64.StdEncoding.EncodeToString(
		binary.LittleEndian.AppendUint64(nil, uint64(paddingNeeded)),
	)

	_, err = fmt.Fprintf(w, "%s%s%s%s", original, separator, padding, sizeMarker)
	return err
}

func unpad(r io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	sepIndex := bytes.Index(data, []byte(separator))
	if sepIndex == -1 {
		return nil, errors.New("invalid format: separator not found. " +
			"Input may not be padded or was corrupted")
	}

	remaining := data[sepIndex+len(separator):]
	sizeMarkerIndex := bytes.Index(remaining, []byte(sizePrefix))
	if sizeMarkerIndex == -1 {
		return nil, errors.New("invalid format: size marker missing")
	}

	sizeData := remaining[sizeMarkerIndex+len(sizePrefix):]
	if len(sizeData) < 12 {
		return nil, errors.New("invalid size marker: too short")
	}

	sizeBytes, err := base64.StdEncoding.DecodeString(string(sizeData))
	if err != nil {
		return nil, fmt.Errorf("invalid size marker: %v", err)
	}
	if len(sizeBytes) != 8 {
		return nil, errors.New("invalid size marker format")
	}
	paddingSize := binary.LittleEndian.Uint64(sizeBytes)

	expectedEnd := sepIndex + len(separator) + int(paddingSize) + len(sizePrefix) + 12
	if len(data) < expectedEnd {
		return nil, fmt.Errorf("corrupted data: expected %d bytes, got %d",
			expectedEnd, len(data))
	}

	return bytes.NewReader(data[:sepIndex]), nil
}

func chunk64(s string) string {
	var buf strings.Builder
	for len(s) > 0 {
		chunkSize := 64
		if len(s) < chunkSize {
			chunkSize = len(s)
		}
		buf.WriteString(s[:chunkSize])
		buf.WriteString("\n")
		s = s[chunkSize:]
	}
	return strings.TrimSpace(buf.String())
}

func generateKeys(outputDir string) error {
	priv, pub, err := generateKeyPair()
	if err != nil {
		return err
	}
	defer priv.Destroy()
	defer pub.Destroy()

	if outputDir == "" {
		outputDir = "."
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("error creating output directory '%s': %v", outputDir, err)
	}

	savePrivPath := filepath.Join(outputDir, privateKeyFilename)
	savePubPath := filepath.Join(outputDir, publicKeyFilename)

	if err := savePEM(savePrivPath, priv, "PRIVATE KEY"); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}
	if err := savePEM(savePubPath, pub, "PUBLIC KEY"); err != nil {
		return fmt.Errorf("failed to save public key: %v", err)
	}
	fmt.Printf("Keys generated and saved:\nPrivate Key: %s\nPublic Key: %s\n", savePrivPath, savePubPath)
	return nil
}

func importKey(name string, keyFile string) error {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	target := name + ".pem"
	err = os.WriteFile(target, data, 0600)
	if err == nil {
		fmt.Printf("Public key imported: %s -> %s\n", keyFile, target)
	}
	return err
}

func processSPE(recipient string, r io.Reader, w io.Writer) error {

	signTemp, err := secureTempFile()
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer cleanupTempFile(signTemp)

	privKeyForSigning, err := loadPrivateKey("")
	if err != nil {
		return fmt.Errorf("failed to load private key for signing: %v", err)
	}
	defer privKeyForSigning.Destroy()

	if err := signMessage(privKeyForSigning, r, signTemp); err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}
	if _, err := signTemp.Seek(0, 0); err != nil {
		return err
	}

	padTemp, err := secureTempFile()
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer cleanupTempFile(padTemp)

	if err := pad(signTemp, padSize, padTemp); err != nil {
		return fmt.Errorf("padding failed: %v", err)
	}
	if _, err := padTemp.Seek(0, 0); err != nil {
		return err
	}

	pubKey, err := loadPublicKey(recipient, "")
	if err != nil {
		return err
	}
	defer pubKey.Destroy()

	if err := encrypt(pubKey, padTemp, w); err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	return nil
}

func processDUV(r io.Reader, w io.Writer) error {

	decryptTemp, err := secureTempFile()
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer cleanupTempFile(decryptTemp)

	privKey, err := loadPrivateKey("")
	if err != nil {
		return err
	}
	defer privKey.Destroy()

	if err := decrypt(privKey, r, decryptTemp); err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}
	if _, err := decryptTemp.Seek(0, 0); err != nil {
		return err
	}

	unpadded, err := unpad(decryptTemp)
	if err != nil {
		return fmt.Errorf("unpadding failed: %v", err)
	}

	unpadTemp, err := secureTempFile()
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer cleanupTempFile(unpadTemp)

	if _, err := io.Copy(unpadTemp, unpadded); err != nil {
		return err
	}
	if _, err := unpadTemp.Seek(0, 0); err != nil {
		return err
	}

	if err := verifyMessage(unpadTemp, w); err != nil {
		return fmt.Errorf("verification failed: %v", err)
	}
	return nil
}

func looksLikePath(s string) bool {
	return strings.ContainsAny(s, "/\\") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

func printUsage() {
	fmt.Println(`Usage: minicrypt [flags] <command> [args]
Commands:
  g [output_directory]    Generate keys (default: current directory)
  i <name> <file>         Import public key (imports 'file' as '<name>.pem' into current directory)
  e [recipient_name_or_pubkey_path] Encrypt
  d [private_key_path]    Decrypt
  s [private_key_path]    Sign
  v                       Verify
  spe <recipient_name>    Sign+Pad+Encrypt (uses private.pem and <recipient_name>.pem in current directory)
  duv                     Decrypt+Unpad+Verify (uses private.pem in current directory)

Flags:
  -p <size>               Set padding size (default: 4096)

Examples:
  # Generate keys in the current directory:
  minicrypt g

  # Generate keys in a specific directory:
  minicrypt g ./my_keys

  # Import Alice's public key and save it as 'alice.pem':
  minicrypt i alice /path/to/alice_public.pem

  # Encrypt to 'alice' (looks for 'alice.pem' in current directory):
  minicrypt e alice < msg.txt > enc.txt

  # Encrypt using a specific public key file (path as argument):
  minicrypt e ./path/to/bob_public.pem < msg.txt > enc.txt

  # Decrypt (looks for 'private.pem' in current directory):
  minicrypt d < enc.txt

  # Decrypt using a specific private key file (path as argument):
  minicrypt d ./path/to/my_custom_private_key.pem < enc.txt

  # Sign a message (looks for 'private.pem' in current directory):
  minicrypt s < message.txt > signed.txt

  # Sign a message using a specific private key file (path as argument):
  minicrypt s ./path/to/my_signing_key.pem < message.txt > signed.txt

  # Combined operations
  minicrypt spe alice < msg.txt > enc.txt
  minicrypt duv < enc.txt
  minicrypt -p 2048 spe bob < msg.txt > enc.txt`)
}

func main() {
	flag.Parse()
	memguard.CatchInterrupt()
	defer memguard.Purge()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}
	cmd := args[0]
	args = args[1:]

	var err error

	switch cmd {
	case "g":
		outputDir := ""
		if len(args) > 0 {
			outputDir = args[0]
		}
		err = generateKeys(outputDir)
	case "i":
		if len(args) < 2 {
			fmt.Println("Usage: minicrypt i <name> <file>")
			os.Exit(1)
		}
		err = importKey(args[0], args[1])
	case "e":
		var pubKey *memguard.LockedBuffer
		var specificKeyPath string
		var recipientName string

		if len(args) == 0 {
			recipientName = "public"
		} else {
			if looksLikePath(args[0]) {
				specificKeyPath = args[0]
			} else {
				recipientName = args[0]
			}
		}

		if specificKeyPath != "" {
			pubKey, err = loadPublicKey("", specificKeyPath)
			if err != nil {
				log.Fatalf("Error loading public key from %s: %v", specificKeyPath, err)
			}
		} else {
			pubKey, err = loadPublicKey(recipientName, "")
			if err != nil {
				log.Fatalf("Error loading public key for recipient %s: %v", recipientName, err)
			}
		}
		defer pubKey.Destroy()
		err = encrypt(pubKey, os.Stdin, os.Stdout)
	case "d":
		var privKey *memguard.LockedBuffer
		specificKeyPath := ""
		if len(args) > 0 && looksLikePath(args[0]) {
			specificKeyPath = args[0]
		}

		privKey, err = loadPrivateKey(specificKeyPath)
		if err != nil {
			if specificKeyPath != "" {
				log.Fatalf("Error loading private key from path %s: %v", specificKeyPath, err)
			} else {
				log.Fatalf("Error loading private key from current directory ('%s'): %v", privateKeyFilename, err)
			}
		}
		defer privKey.Destroy()
		err = decrypt(privKey, os.Stdin, os.Stdout)
	case "s":
		var privKey *memguard.LockedBuffer
		specificKeyPath := ""
		if len(args) > 0 && looksLikePath(args[0]) {
			specificKeyPath = args[0]
		}

		privKey, err = loadPrivateKey(specificKeyPath)
		if err != nil {
			if specificKeyPath != "" {
				log.Fatalf("Error loading private key for signing from path %s: %v", specificKeyPath, err)
			} else {
				log.Fatalf("Error loading private key for signing from current directory ('%s'): %v", privateKeyFilename, err)
			}
		}
		defer privKey.Destroy()
		err = signMessage(privKey, os.Stdin, os.Stdout)
	case "v":
		err = verifyMessage(os.Stdin, os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
	case "p":
		if len(args) < 1 {
			fmt.Println("Usage: minicrypt p <size>")
			os.Exit(1)
		}
		var size int
		size, err = strconv.Atoi(args[0])
		if err != nil {
			log.Fatal(err)
		}
		err = pad(os.Stdin, size, os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
	case "u":
		var r io.Reader
		r, err = unpad(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(os.Stdout, r)
	case "spe":
		if len(args) < 1 {
			fmt.Println("Usage: minicrypt spe <recipient>")
			os.Exit(1)
		}
		err = processSPE(args[0], os.Stdin, os.Stdout)
	case "duv":
		err = processDUV(os.Stdin, os.Stdout)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatal(err)
	}
}
