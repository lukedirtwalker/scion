// Package mgmtapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package mgmtapi

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}