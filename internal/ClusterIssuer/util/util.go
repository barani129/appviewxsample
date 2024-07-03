package util

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barani129/appviewx/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ServerResponse struct {
	Response      string `json:"response"`
	Message       any    `json:"message"`
	AppStatusCode any    `json:"appStatusCode"`
	Tags          struct {
	} `json:"tags"`
	Headers any `json:"headers"`
}

type AppResponse struct {
	Response struct {
		HTTPStatusCode int `json:"httpStatusCode"`
		Response       struct {
			Objects []struct {
				CommonName              string   `json:"commonName"`
				SerialNumber            string   `json:"serialNumber"`
				IssuerCommonName        string   `json:"issuerCommonName"`
				Status                  string   `json:"status"`
				AvxStatus               string   `json:"avxStatus"`
				AssociatedObjects       []any    `json:"associatedObjects"`
				DiscoverySources        []any    `json:"discoverySources"`
				SubjectOrganization     string   `json:"subjectOrganization"`
				SubjectOrganizationUnit string   `json:"subjectOrganizationUnit"`
				SubjectLocality         string   `json:"subjectLocality"`
				SubjectState            string   `json:"subjectState"`
				SubjectCountry          string   `json:"subjectCountry"`
				IssuerOrganization      string   `json:"issuerOrganization"`
				IssuerOrganizationUnit  string   `json:"issuerOrganizationUnit"`
				IssuerLocality          string   `json:"issuerLocality"`
				IssuerState             string   `json:"issuerState"`
				IssuerCountry           string   `json:"issuerCountry"`
				Version                 string   `json:"version"`
				ValidFrom               int64    `json:"validFrom"`
				ValidTo                 int64    `json:"validTo"`
				FirstDiscoveryDate      int      `json:"firstDiscoveryDate"`
				LastBeforeDiscoveryDate int      `json:"lastBeforeDiscoveryDate"`
				LastDiscoveryDate       int      `json:"lastDiscoveryDate"`
				ValidFor                string   `json:"validFor"`
				KeyAlgorithmAndSize     string   `json:"keyAlgorithmAndSize"`
				SignatureAlgorithm      string   `json:"signatureAlgorithm"`
				SignatureHashAlgorithm  string   `json:"signatureHashAlgorithm"`
				KeyUsage                string   `json:"keyUsage"`
				ExtendedKeyUsage        string   `json:"extendedKeyUsage"`
				BasicConstraints        string   `json:"basicConstraints"`
				Group                   string   `json:"group"`
				SubjectAlternativeNames []any    `json:"subjectAlternativeNames"`
				ComplianceStatus        string   `json:"complianceStatus"`
				Applications            []any    `json:"applications"`
				PolicyIdentifiers       []any    `json:"policyIdentifiers"`
				ExpiryStatus            string   `json:"expiryStatus"`
				Permission              string   `json:"permission"`
				Category                string   `json:"category"`
				UUID                    string   `json:"uuid"`
				CertificateAuthority    string   `json:"certificateAuthority"`
				AuthorityKeyIdentifier  string   `json:"authorityKeyIdentifier"`
				SubjectKeyIdentifier    string   `json:"subjectKeyIdentifier"`
				IssuerSerialNumber      string   `json:"issuerSerialNumber"`
				AuthorityInfoAccess     []string `json:"authorityInfoAccess"`
				CertificatePolicies     []any    `json:"certificatePolicies"`
				CrlDistributionPoints   []string `json:"crlDistributionPoints"`
				ThumbprintAlgorithm     string   `json:"thumbprintAlgorithm"`
				ThumbPrint              string   `json:"thumbPrint"`
				Type                    string   `json:"type"`
				CsrGenerationSource     string   `json:"csrGenerationSource"`
				CertificateHSMDetails   struct {
					AutoFilled bool `json:"autoFilled"`
				} `json:"certificateHSMDetails,omitempty"`
				DeviceDetails struct {
				} `json:"deviceDetails,omitempty"`
				NewConnectors             []any    `json:"newConnectors"`
				CsrAvailable              bool     `json:"csrAvailable"`
				AutoRenewDate             string   `json:"autoRenewDate"`
				MissingParamsForAutoRenew string   `json:"missingParamsForAutoRenew"`
				SuspendedCertificate      bool     `json:"suspendedCertificate"`
				MailAddress               string   `json:"mailAddress"`
				StreetAddress             string   `json:"streetAddress"`
				PostalCode                string   `json:"postalCode"`
				RequestIds                []string `json:"requestIds"`
				OrderID                   string   `json:"orderId"`
				PublicKey                 string   `json:"publicKey"`
				IssuedByRootCertificate   bool     `json:"issuedByRootCertificate"`
				CumulativeSanCount        int      `json:"cumulativeSanCount"`
				ChainPriority             int      `json:"chainPriority"`
				Subject                   string   `json:"subject"`
				Cvss                      float64  `json:"cvss"`
				PrivatekeyAvaliable       bool     `json:"privatekeyAvaliable"`
				ResourceID                string   `json:"resourceId"`
			} `json:"objects"`
			TotalRecords        int `json:"totalRecords"`
			ObtainedRecords     int `json:"obtainedRecords"`
			ObtainedRecordRange struct {
				Start int `json:"start"`
				End   int `json:"end"`
			} `json:"obtainedRecordRange"`
		} `json:"response"`
		Message       string `json:"message"`
		AppStatusCode any    `json:"appStatusCode"`
		Tags          any    `json:"tags"`
	} `json:"response"`
	Message       any `json:"message"`
	AppStatusCode any `json:"appStatusCode"`
	Tags          struct {
	} `json:"tags"`
	Headers any `json:"headers"`
}

type CreationResponse struct {
	Response struct {
		EncodedFormat      string `json:"encodedFormat"`
		ResourceID         string `json:"resourceId"`
		CertificateContent string `json:"certificateContent"`
		RequestID          string `json:"requestId"`
		CertificateName    string `json:"certificateName"`
	} `json:"response"`
	Message       string `json:"message"`
	AppStatusCode any    `json:"appStatusCode"`
	Tags          struct {
	} `json:"tags"`
	Headers any `json:"headers"`
}

type Certificate struct {
	CommonName              string   `json:"commonName"`
	SerialNumber            string   `json:"serialNumber"`
	IssuerCommonName        string   `json:"issuerCommonName"`
	Status                  string   `json:"status"`
	AvxStatus               string   `json:"avxStatus"`
	AssociatedObjects       []any    `json:"associatedObjects"`
	DiscoverySources        []any    `json:"discoverySources"`
	SubjectOrganization     string   `json:"subjectOrganization"`
	SubjectOrganizationUnit string   `json:"subjectOrganizationUnit"`
	SubjectLocality         string   `json:"subjectLocality"`
	SubjectState            string   `json:"subjectState"`
	SubjectCountry          string   `json:"subjectCountry"`
	IssuerOrganization      string   `json:"issuerOrganization"`
	IssuerOrganizationUnit  string   `json:"issuerOrganizationUnit"`
	IssuerLocality          string   `json:"issuerLocality"`
	IssuerState             string   `json:"issuerState"`
	IssuerCountry           string   `json:"issuerCountry"`
	Version                 string   `json:"version"`
	ValidFrom               int64    `json:"validFrom"`
	ValidTo                 int64    `json:"validTo"`
	FirstDiscoveryDate      int      `json:"firstDiscoveryDate"`
	LastBeforeDiscoveryDate int      `json:"lastBeforeDiscoveryDate"`
	LastDiscoveryDate       int      `json:"lastDiscoveryDate"`
	ValidFor                string   `json:"validFor"`
	KeyAlgorithmAndSize     string   `json:"keyAlgorithmAndSize"`
	SignatureAlgorithm      string   `json:"signatureAlgorithm"`
	SignatureHashAlgorithm  string   `json:"signatureHashAlgorithm"`
	KeyUsage                string   `json:"keyUsage"`
	ExtendedKeyUsage        string   `json:"extendedKeyUsage"`
	BasicConstraints        string   `json:"basicConstraints"`
	Group                   string   `json:"group"`
	SubjectAlternativeNames []any    `json:"subjectAlternativeNames"`
	ComplianceStatus        string   `json:"complianceStatus"`
	Applications            []any    `json:"applications"`
	PolicyIdentifiers       []any    `json:"policyIdentifiers"`
	ExpiryStatus            string   `json:"expiryStatus"`
	Permission              string   `json:"permission"`
	Category                string   `json:"category"`
	UUID                    string   `json:"uuid"`
	CertificateAuthority    string   `json:"certificateAuthority"`
	AuthorityKeyIdentifier  string   `json:"authorityKeyIdentifier"`
	SubjectKeyIdentifier    string   `json:"subjectKeyIdentifier"`
	IssuerSerialNumber      string   `json:"issuerSerialNumber"`
	AuthorityInfoAccess     []string `json:"authorityInfoAccess"`
	CertificatePolicies     []any    `json:"certificatePolicies"`
	CrlDistributionPoints   []string `json:"crlDistributionPoints"`
	ThumbprintAlgorithm     string   `json:"thumbprintAlgorithm"`
	ThumbPrint              string   `json:"thumbPrint"`
	Type                    string   `json:"type"`
	CsrGenerationSource     string   `json:"csrGenerationSource"`
	CertificateHSMDetails   struct {
		AutoFilled bool `json:"autoFilled"`
	} `json:"certificateHSMDetails,omitempty"`
	DeviceDetails struct {
	} `json:"deviceDetails,omitempty"`
	NewConnectors             []any    `json:"newConnectors"`
	CsrAvailable              bool     `json:"csrAvailable"`
	AutoRenewDate             string   `json:"autoRenewDate"`
	MissingParamsForAutoRenew string   `json:"missingParamsForAutoRenew"`
	SuspendedCertificate      bool     `json:"suspendedCertificate"`
	MailAddress               string   `json:"mailAddress"`
	StreetAddress             string   `json:"streetAddress"`
	PostalCode                string   `json:"postalCode"`
	RequestIds                []string `json:"requestIds"`
	OrderID                   string   `json:"orderId"`
	PublicKey                 string   `json:"publicKey"`
	IssuedByRootCertificate   bool     `json:"issuedByRootCertificate"`
	CumulativeSanCount        int      `json:"cumulativeSanCount"`
	ChainPriority             int      `json:"chainPriority"`
	Subject                   string   `json:"subject"`
	Cvss                      float64  `json:"cvss"`
	PrivatekeyAvaliable       bool     `json:"privatekeyAvaliable"`
	ResourceID                string   `json:"resourceId"`
}

func GetSpecAndStatus(clusterissuer client.Object) (*v1alpha1.ClusterIssuerSpec, *v1alpha1.ClusterIssuerStatus, error) {
	switch t := clusterissuer.(type) {
	case *v1alpha1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an cluster issuer type: %t", t)
	}
}

func GetReadyCondition(status *v1alpha1.ClusterIssuerStatus) *v1alpha1.ClusterIssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == v1alpha1.ClusterIssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *v1alpha1.ClusterIssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == v1alpha1.ConditionTrue
	}
	return false
}

func SetReadyCondition(status *v1alpha1.ClusterIssuerStatus, conditionStatus v1alpha1.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &v1alpha1.ClusterIssuerCondition{
			Type: v1alpha1.ClusterIssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == v1alpha1.ClusterIssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetAPIAliveness(spec *v1alpha1.ClusterIssuerSpec) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	nurl := strings.SplitAfter(spec.URL, ":443")
	url := nurl[0]
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return err
	}
	return nil

}

func GetToken(spec *v1alpha1.ClusterIssuerSpec, username string, password string) (string, error) {
	url := spec.URL
	nurl := url + "/acctmgmt-get-service-token?gwsource=external"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	var data = strings.NewReader(`grant_type=client_credentials`)
	req, err := http.NewRequest("POST", nurl, data)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Basic "+basicAuth(username, password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return "", err
	}
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var x ServerResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return "", err
	}
	return x.Response, nil

}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func SearchCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, cn string) ([]byte, int, error) {
	url := spec.URL
	nurl := url + "/certificate/search?gwsource=external"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	var data = strings.NewReader(fmt.Sprintf(`{"input":{"category":"Server","keywordSearch" : {"subject:cn":"%s"}},"filter":{"max":"100","start":"1","sortColumn":"commonName","sortOrder":"desc"}}`, cn))
	req, err := http.NewRequest("POST", nurl, data)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, resp.StatusCode, fmt.Errorf("certificate not found")
	}
	if resp.StatusCode != 200 || resp == nil {
		return nil, 0, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	var x AppResponse
	err = json.Unmarshal([]byte(body), &x)
	if err != nil {
		return nil, 0, err
	}
	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		for range x.Response.Response.Objects {
			if x.Response.Response.Objects[i].ExpiryStatus == "Valid" {
				return []byte(fmt.Sprintf("%v", x.Response.Response.Objects[i])), 200, nil
			}
		}
	}
	return nil, 0, err
}

func APICertificateHandler(spec *v1alpha1.ClusterIssuerSpec, token string, csr string, cn string) ([]byte, error) {
	certificate, code, err := SearchCertificate(spec, token, cn)
	if code == 200 && certificate != nil {
		return certificate, nil
	}
	if code == 404 {
		//Certificate not found
		certificate, code, err := CreateCertificate(spec, token, csr, cn)
		if code != 200 || err != nil {
			return nil, fmt.Errorf("failed to create a new certificate for common name %s", cn)
		}
		return certificate, nil
	}
	if certificate != nil && code == 999 {
		//logic for renewing the expired certificate
		var x Certificate
		json.Unmarshal(certificate, &x)
		cert, code, err := RenewCertificate(spec, token, cn, x.ResourceID, x.SerialNumber)
		if err != nil || code != 200 {
			return nil, err
		}
		return cert, nil
	}
	if code == 998 {
		return nil, err
	}
	return nil, err
}

func CreateCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, csr string, cn string) (certificate []byte, code int, err error) {
	url := spec.URL
	nurl := url + "/certificate/create?gwsource=external&isSync=true&ttl=300"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	ndata := strings.NewReader(fmt.Sprintf(`{
		"csrGenerationSource": "uploadCSR",
		"caConnectorInfo": {
			"certificateAuthority": "AppViewX",
			"isAutoRenewal": false,
			"autoRegenerateEnabled": false,
			"caSettingName": "NON PROD Appviewx CA",
			"validityUnitValue": "1",
			"validityInDays": 1,
			"validityUnit": "days"
		},
		"certificateGroup": {
			"name": "Kubernetes-5G-Automation"
		},
		"uploadCsrDetails": {
			"csrContent": "%v",
			"category": "Server"
		},
		"certificateFormat": {
			"format": "PEM",
			"password": ""
		}
	}`, csr))
	// data := strings.NewReader(fmt.Sprintf(`{"csrGenerationSource": "appviewx","caConnectorInfo": {"certificateAuthority": "AppViewX","isAutoRenewal": false,"autoRegenerateEnabled": false,"caSettingName": "NON PROD Appviewx CA","csrParameters": {"commonName": "%s","certificateCategories": ["Server","Client"]},"validityUnitValue": "1","validityInDays": 365,"validityUnit": "years"},"certificateGroup": {"name": "Kubernetes-5G-Automation"},"certificateFormat": {"format": "PEM","password": ""}}`, cn))
	req, err := http.NewRequest("POST", nurl, ndata)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return nil, 0, err
	}
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	var x CreationResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return nil, 0, err
	}
	return []byte(fmt.Sprintf("%v", x.Response.CertificateContent)), 200, nil
}

func RenewCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, cn string, resourceid string, serialnumber string) (certificate []byte, code int, err error) {
	url := spec.URL
	nurl := url + "/certificate/renew?gwsource=external&isSync=true&ttl=300"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   50 * time.Second,
		Transport: tr,
	}
	var data = strings.NewReader(fmt.Sprintf(`{"resourceId": "%s","commonName": "%s","serialNumber": "%s","action": "renew","certificateFormat":{"format" : "PEM","password" : ""}}`, resourceid, cn, serialnumber))
	req, err := http.NewRequest("PUT", nurl, data)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp == nil {
		return nil, 0, err
	}
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	var x CreationResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return nil, 0, err
	}
	return []byte(fmt.Sprintf("%v", x.Response.CertificateContent)), 200, nil
}
