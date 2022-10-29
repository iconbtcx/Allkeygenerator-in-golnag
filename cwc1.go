package main

import (
    "os"
    "fmt"
    "flag"
    "encoding/hex"
    "crypto/aes"
    "crypto/sha512"
    "crypto/sha256"
    "crypto/cipher"

    "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type ConfigWallet struct {
	Salt             string
	DeriveIterations uint32
	Crypted_key      string
	Ckey             string
	Pubkey           string
}

var walletOptions = ConfigWallet {
    Salt: "d2542bb38e0ee061",
    DeriveIterations: 76753,
    Crypted_key: "9cf74f8693f8c1ad26a9e9c92894bc81f0ef639cd01bb26805c190e0aeba006fbdd6b817e0b6634b0fb11944bc0f19eb",
    Ckey: "de1dd215480b1e77319082a1d1f5bd4ba086728e0c9ad21bfdb2d65d379522ee26b1d3ef38cc4c9fb4c6370e2d57af75",
    Pubkey: "025ad9cc469e32ea3d294a152b78bfded6ad47cfb9d5d9e52e201cd93d0c05fae1",
}

var m_pubkey_hash = GetPubkeyHash()

var m_curve = secp256k1.S256()

// Calc pubkey hash
func GetPubkeyHash() []byte {
    pubkey_bc, _ := hex.DecodeString("03" + walletOptions.Pubkey)
    data := sha256.Sum256(pubkey_bc)
    data = sha256.Sum256(data[:])
    return data[:]
}

// Generate private key
func GenPrivateKey(password string) []byte {
    salt, _ := hex.DecodeString(walletOptions.Salt)
    data := sha512.Sum512([]byte(password + string(salt)))
    for i := uint32(1); i < walletOptions.DeriveIterations; i++ {
        data = sha512.Sum512(data[:])
    }
    chKey := data[0:32]
    chIV := data[32:48]

    block, _ := aes.NewCipher(chKey)
    cbc := cipher.NewCBCDecrypter(block, chIV)
    crypted_key, _ := hex.DecodeString(walletOptions.Crypted_key)
    cbc.CryptBlocks(crypted_key, crypted_key)

    chKey = crypted_key[0:32]
    chIV = m_pubkey_hash[0:16]

    block, _ = aes.NewCipher(chKey)
    cbc = cipher.NewCBCDecrypter(block, chIV)
    ckey, _ := hex.DecodeString(walletOptions.Ckey)
    cbc.CryptBlocks(ckey, ckey)

    return ckey[0:32]
}


// Check password
func CheckPassword(password string) bool {
    secret := GenPrivateKey(password)
    x, _ := m_curve.ScalarBaseMult(secret)
    return x.Text(16) == walletOptions.Pubkey
}

func main() {
    flag.Parse()
    if flag.NArg() == 0 {
        fmt.Printf("Usage: %s password\n", os.Args[0])
        os.Exit(1)
    }

    password := flag.Args()[0]
    fmt.Printf("%s: %t\n", password, CheckPassword(password))
}