package main

import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

//export verifyGo
func verifyGo(
	layoutPath string,
	pubKeyPaths []string,
	intermediatePaths []string,
	linkDir string,
	lineNormalizationInt int) *C.char {
	var layoutMb intoto.Metablock

	if err := layoutMb.Load(layoutPath); err != nil {
		e := fmt.Errorf("failed to load layout at %s: %w", layoutPath, err)
		return C.CString("Error:: " + e.Error())
	}

	pubKeyCount := len(pubKeyPaths)
	layoutKeys := make(map[string]intoto.Key, pubKeyCount)

	for _, pubKeyPath := range pubKeyPaths {
		var pubKey intoto.Key
		if err := pubKey.LoadKeyDefaults(pubKeyPath); err != nil {
			e := fmt.Errorf("invalid key at %s: %w", pubKeyPath, err)
			return C.CString("Error:: " + e.Error())
		}

		layoutKeys[pubKey.KeyID] = pubKey
	}

	intermediatePathCount := len(intermediatePaths)
	intermediatePems := make([][]byte, 0, int(intermediatePathCount))

	for _, intermediate := range intermediatePaths {
		f, err := os.Open(intermediate)
		if err != nil {
			e := fmt.Errorf("failed to open intermediate %s: %w", intermediate, err)
			return C.CString("Error:: " + e.Error())
		}
		defer f.Close()

		pemBytes, err := io.ReadAll(f)
		if err != nil {
			e := fmt.Errorf("failed to read intermediate %s: %w", intermediate, err)
			return C.CString("Error:: " + e.Error())
		}

		intermediatePems = append(intermediatePems, pemBytes)

		if err := f.Close(); err != nil {
			e := fmt.Errorf("could not close intermediate cert: %w", err)
			return C.CString("Error:: " + e.Error())
		}
	}

	var lineNormalization bool
	if lineNormalizationInt == 0 {
		lineNormalization = false
	} else {
		lineNormalization = true
	}

	summaryLink, err := intoto.InTotoVerify(layoutMb, layoutKeys, linkDir, "", make(map[string]string), intermediatePems, lineNormalization)
	if err != nil {
		e := fmt.Errorf("inspection failed: %w", err)
		return C.CString("Error:: " + e.Error())
	}

	jsonBytes, err := json.Marshal(summaryLink)
	if err != nil {
		e := fmt.Errorf("json failed: %w", err)
		return C.CString("Error:: " + e.Error())
	}

	return C.CString(string(jsonBytes))
}
