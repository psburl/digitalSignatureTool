package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	st "./signaturetools"
)

func main() {

	function := flag.String("f", "genkey", "defines function to be processed")
	pemFile := flag.String("k", "", "defines path of key to be used on function")
	file := flag.String("i", "", "defines path of message input")
	flag.Parse()

	if *function == "genkey" {
		st.GenerateKeys()
	} else if *function == "sign" {

		text, err := ioutil.ReadFile(*file)

		if err != nil {
			fmt.Println("Error reading input file:", err.Error())
			os.Exit(1)
		}

		privateKey, err := st.ReadPrivateKey(*pemFile)
		if err != nil {
			fmt.Println("Error reading privateKey:", err.Error())
			os.Exit(1)
		}

		signMessage := st.SignText(string(text), privateKey)
		json, _ := json.Marshal(&signMessage)
		os.Mkdir("signed-messages", os.ModePerm)
		ioutil.WriteFile("signed-messages/message.signed", json, 0644)

	} else if *function == "verify" {

		text, err := ioutil.ReadFile(*file)
		var signMessage st.SignMessage
		err = json.Unmarshal(text, &signMessage)

		if err != nil {
			fmt.Println("Error reading input file:", err.Error())
			os.Exit(1)
		}

		publicKey, err := st.ReadPublicKey(*pemFile)
		if err != nil {
			fmt.Println("Error reading publicKey:", err.Error())
			os.Exit(1)
		}

		verify, err := st.VerifySign(signMessage, publicKey)

		if verify {
			fmt.Println("Verification PASSED")
		} else {
			fmt.Println("Verification ERROR ", err.Error())
		}

	} else {
		fmt.Println("undefined function ", *function, " in [genkey, sign, verify]")
	}
}
