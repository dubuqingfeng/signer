package bip39

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Word bit length
	wordBitLen    = 11
	Pbkdf2Rounds  = 2048
	Pbkdf2SeedLen = 64
)

// NewMnemonicFromEntropy generates a new mnemonic from a byte slice
func NewMnemonicFromEntropy(entropy Entropy) (string, error) {
	// 先校验 Entropy 的长度是否符合要求
	err := validateEntropyBitLen(len(entropy.bits) * 8)
	if err != nil {
		return "", err
	}

	// 将 Entropy 转换为字节数组
	var entropyBuff bytes.Buffer
	for _, b := range entropy.bits {
		entropyBuff.WriteString(fmt.Sprintf("%.8b", b))
	}
	// 计算 checkSum
	checkSumBinStr := entropyCheckSumBinStr(entropy.bits)
	mnemonicBinStr := entropyBuff.String() + checkSumBinStr

	// 创建 slice 存储 mnemonicBinStr 中的每一个字符
	mnemonicLen := len(mnemonicBinStr) / wordBitLen
	mnemonic := make([]string, 0, mnemonicLen)

	for i := 0; i < mnemonicLen; i++ {
		wordStrBin := mnemonicBinStr[i*wordBitLen : (i+1)*wordBitLen]
		wordIdx, _ := strconv.ParseInt(wordStrBin, 2, 16)
		mnemonic = append(mnemonic, english[wordIdx])
	}

	return strings.Join(mnemonic, " "), nil
}

// NewSeedFromMnemonic generates a seed from a mnemonic, and a password
func NewSeedFromMnemonic(words, passphrase string) ([]byte, error) {
	// 先校验 mnemonic 的长度是否符合要求, 并且是否含有空格， 以及是否在 words 中
	err := validateMnemonic(words)
	if err != nil {
		return nil, err
	}
	// Get salt
	salt := "mnemonic" + passphrase
	// Generate seed
	return pbkdf2.Key([]byte(words), []byte(salt), Pbkdf2Rounds, Pbkdf2SeedLen, sha512.New), nil
}

// validateMnemonic checks if a mnemonic is valid
func validateMnemonic(words string) error {
	// 先校验 mnemonic 的长度是否符合要求
	wordsLen := len(strings.Split(words, " "))
	if wordsLen < 12 || wordsLen > 24 {
		return fmt.Errorf("mnemonic must be 12-24 words")
	}
	// 再校验 mnemonic 中是否含有空格
	if strings.Contains(words, " ") {
		return fmt.Errorf("mnemonic must not contain spaces")
	}
	// 临时遍历到 map
	var englishWordsMap map[string]int
	englishWordsMap = make(map[string]int)
	for i, word := range english {
		englishWordsMap[word] = i
	}
	// 是否在 words 中
	for _, word := range strings.Split(words, " ") {
		if _, ok := englishWordsMap[word]; !ok {
			return fmt.Errorf("mnemonic must contain only words in the english dictionary")
		}
	}
	return nil
}

// entropyCheckSumBinStr will return the checksum for the given entropy bits
func entropyCheckSumBinStr(slice []byte) string {
	hash := sha256.Sum256(slice)
	var hashBuffer bytes.Buffer
	for _, b := range hash {
		hashBuffer.WriteString(fmt.Sprintf("%.8b", b))
	}
	hashStr := hashBuffer.String()
	checkSumBitLen := len(slice) / 4

	return hashStr[:checkSumBitLen]
}
