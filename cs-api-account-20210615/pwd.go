package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	fmt.Println("Hello")

	stored := "cl=pre$j_a!m#%iku-h@zyqngbdv(wfo)*NM80TO42RDWAI6JQZLP9EHK1XSGUVY3F0dfd7304e199fd1ad2e521246005c91e7f33bbcbd4fcc83dc376f4488644779222bedebff25e20b343ad2c2f5359388057b0"
	salt := stored[0:66]
	encoded := stored[66:len(stored)]
	enteredPass := "afutoxs#P8IG2S"

	temp := pbkdf2.Key([]byte(enteredPass), []byte(salt), 10000, 50, sha256.New)
	//fmt.Println(temp)
	fmt.Println("****calculated")
	fmt.Println(fmt.Sprintf("%x", temp))
	fmt.Println("****encoded ")
	fmt.Println(encoded)
	fmt.Println("****salt")
	fmt.Println(salt)
}
