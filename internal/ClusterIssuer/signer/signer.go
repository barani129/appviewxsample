/*
Copyright 2024 baranitharan.chittharanjan@spark.co.nz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package signer

import (
	"fmt"
	"strings"

	"github.com/barani129/appviewx/api/v1alpha1"
	certmutil "github.com/barani129/appviewx/internal/ClusterIssuer/util"
)

func ParseCommonName(csrbytes []byte) (string, error) {
	csr, err := parseCSR(csrbytes)
	if err != nil {
		return "", err
	}
	cn := csr.Subject.CommonName
	return cn, nil
}

func SearchCertificate(spec *v1alpha1.ClusterIssuerSpec, csr string, commonName string, username string, password string, interCert string) ([]byte, error) {
	token, err := certmutil.GetToken(spec, username, password)
	if err != nil {
		return nil, err
	}
	//Search remote API for the certificate
	certificate, err := certmutil.APICertificateHandler(spec, token, csr, commonName, interCert)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, fmt.Errorf("certificate is empty, unable to handle certificate requests for common name %s", commonName)
	}
	return certificate, nil
}

func ModifyString(cert string) string {
	ncert := strings.TrimPrefix(cert, "-----BEGIN CERTIFICATE REQUEST-----")
	ncert = strings.TrimSuffix(ncert, "-----END CERTIFICATE REQUEST-----")
	// ncert = strings.Trim(ncert, "\n")
	ncert2 := strings.Split(ncert, "\n")
	var cert2 string
	for i := 0; i < len(ncert2); i++ {
		if ncert2[i] != "" {
			ncert2[i] = strings.Trim(ncert2[i], "	")
			if i != 0 {
				cert2 = cert2 + `\n` + ncert2[i]
			}
		}
	}
	ncert3 := "-----BEGIN CERTIFICATE REQUEST-----" + cert2 + "-----END CERTIFICATE REQUEST-----"
	return ncert3
}
