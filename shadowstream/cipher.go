package shadowstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"strconv"

	"github.com/Yawning/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
)

// Cipher generates a pair of stream ciphers for encryption and decryption.
type Cipher interface {
	IVSize() int
	Encrypter(iv []byte) cipher.Stream
	Decrypter(iv []byte) cipher.Stream
}

type KeySizeError int

func (e KeySizeError) Error() string {
	return "key size error: need " + strconv.Itoa(int(e)) + " bytes"
}

// CTR mode
type ctrStream struct{ cipher.Block }

func (b *ctrStream) IVSize() int                       { return b.BlockSize() }
func (b *ctrStream) Decrypter(iv []byte) cipher.Stream { return b.Encrypter(iv) }
func (b *ctrStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCTR(b, iv) }

func AESCTR(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrStream{blk}, nil
}

// CFB mode
type cfbStream struct{ cipher.Block }

func (b *cfbStream) IVSize() int                       { return b.BlockSize() }
func (b *cfbStream) Decrypter(iv []byte) cipher.Stream { return cipher.NewCFBDecrypter(b, iv) }
func (b *cfbStream) Encrypter(iv []byte) cipher.Stream { return cipher.NewCFBEncrypter(b, iv) }

func AESCFB(key []byte) (Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cfbStream{blk}, nil
}

// IETF-variant of chacha20
type chacha20ietfkey []byte

func (k chacha20ietfkey) IVSize() int                       { return chacha20.INonceSize }
func (k chacha20ietfkey) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k chacha20ietfkey) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(k, iv)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Chacha20IETF(key []byte) (Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, KeySizeError(chacha20.KeySize)
	}
	return chacha20ietfkey(key), nil
}

type xchacha20key []byte

func (k xchacha20key) IVSize() int                       { return chacha20.XNonceSize }
func (k xchacha20key) Decrypter(iv []byte) cipher.Stream { return k.Encrypter(iv) }
func (k xchacha20key) Encrypter(iv []byte) cipher.Stream {
	ciph, err := chacha20.NewCipher(k, iv)
	if err != nil {
		panic(err) // should never happen
	}
	return ciph
}

func Xchacha20(key []byte) (Cipher, error) {
	if len(key) != chacha20.KeySize {
		return nil, KeySizeError(chacha20.KeySize)
	}
	return xchacha20key(key), nil
}

// RC4-MD5
type rc4md5key []byte

func (k rc4md5key) IVSize() int                       { return 16 }
func (k rc4md5key) Decrypter(iv []byte) cipher.Stream { return newRC4MD5Stream(k, iv) }
func (k rc4md5key) Encrypter(iv []byte) cipher.Stream { return newRC4MD5Stream(k, iv) }

func newRC4MD5Stream(key, iv []byte) cipher.Stream {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	stream, err := rc4.NewCipher(rc4key)
	if err != nil {
		panic(err)
	}
	return stream
}

func RC4MD5(key []byte) (Cipher, error) {
	return rc4md5key(key), nil
}

// Salsa20
type salsa20key []byte

func (k salsa20key) IVSize() int                       { return 8 }
func (k salsa20key) Decrypter(iv []byte) cipher.Stream { return newSalsa20Stream(k, iv) }
func (k salsa20key) Encrypter(iv []byte) cipher.Stream { return newSalsa20Stream(k, iv) }

func newSalsa20Stream(key, iv []byte) cipher.Stream {
	var c salsaStreamCipher
	copy(c.nonce[:], iv[:8])
	copy(c.key[:], key[:32])
	return &c
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

func (c *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	var buf []byte
	padLen := c.counter % 64
	dataSize := len(src) + padLen
	if cap(dst) >= dataSize {
		buf = dst[:dataSize]
	} else if leakyBufSize >= dataSize {
		buf = leakyBuf.Get()
		defer leakyBuf.Put(buf)
		buf = buf[:dataSize]
	} else {
		buf = make([]byte, dataSize)
	}

	var subNonce [16]byte
	copy(subNonce[:], c.nonce[:])
	binary.LittleEndian.PutUint64(subNonce[len(c.nonce):], uint64(c.counter/64))

	// It's difficult to avoid data copy here. src or dst maybe slice from
	// Conn.Read/Write, which can't have padding.
	copy(buf[padLen:], src[:])
	salsa.XORKeyStream(buf, buf, &subNonce, &c.key)
	copy(dst, buf[padLen:])

	c.counter += len(src)
}

func Salsa20(key []byte) (Cipher, error) {
	return salsa20key(key), nil
}
