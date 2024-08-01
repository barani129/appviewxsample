package signer

import (
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
	if err != nil || certificate == nil {
		return nil, err
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
