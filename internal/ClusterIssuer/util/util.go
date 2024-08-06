package util

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/barani129/appviewx/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type RevokeResponse struct {
	Response struct {
		ResourceID string `json:"resourceId"`
		CertStatus string `json:"certStatus"`
		RequestID  string `json:"requestId"`
	} `json:"response"`
	Message       string `json:"message"`
	AppStatusCode string `json:"appStatusCode"`
	Tags          struct {
	} `json:"tags"`
	Headers any `json:"headers"`
}

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
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
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
	aurl := spec.URL
	nurl := aurl + "/acctmgmt-get-service-token?gwsource=external"
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return "", err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
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
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 || resp == nil {
		return "", fmt.Errorf("unable to retrieve token from the backend %s, message body %s", aurl, string(bodyText))
	}
	var x ServerResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return "", err
	}
	if x.Response == "" {
		return "", fmt.Errorf("token is empty, unable to retrieve authentication token from backend %s", aurl)
	}
	return x.Response, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func SearchCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, cn string) (string, string, bool, int, error) {
	aurl := spec.URL
	nurl := aurl + "/certificate/search?gwsource=external"
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return "", "", false, 0, err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	var data = strings.NewReader(fmt.Sprintf(`{"input":{"category":"Server","keywordSearch" : {"subject:cn":"%s"}},"filter":{"max":"100","start":"1","sortColumn":"commonName","sortOrder":"desc"}}`, cn))
	req, err := http.NewRequest("POST", nurl, data)
	if err != nil {
		return "", "", false, 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", false, 0, err
	}
	if resp.StatusCode == 404 {
		return "", "", false, resp.StatusCode, nil
	}
	if resp.StatusCode != 200 || resp == nil {
		return "", "", false, 0, fmt.Errorf("unable to search certificate for common name %s, message body %s", cn, string(body))
	}
	var x AppResponse
	err = json.Unmarshal([]byte(body), &x)
	if err != nil {
		return "", "", false, 0, err
	}
	var validCerts []string
	if len(x.Response.Response.Objects) < 1 {
		return "", "", false, 404, nil
	}
	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		if x.Response.Response.Objects[i].ExpiryStatus == "New Certificate" {
			// return early with a pending certificate if found
			return "", "", true, 997, nil
		}
	}
	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		if x.Response.Response.Objects[i].ExpiryStatus == "Valid" || strings.Contains(x.Response.Response.Objects[i].ExpiryStatus, "Expiry") {
			validCerts = append(validCerts, x.Response.Response.Objects[i].ResourceID)
		}
	}
	// exiting if more than one valid certificate is found
	if len(validCerts) > 1 {
		return "", "", true, 998, nil
	}

	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		if x.Response.Response.Objects[i].ExpiryStatus == "Valid" || strings.Contains(x.Response.Response.Objects[i].ExpiryStatus, "Expiry") {
			// return early with a valid certificate if found
			return x.Response.Response.Objects[i].ResourceID, x.Response.Response.Objects[i].SerialNumber, true, 200, nil
		}
	}
	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		if x.Response.Response.Objects[i].ExpiryStatus == "Revoked" {
			return "", "", true, 996, nil
		}
	}
	for i := 0; i < (len(x.Response.Response.Objects)); i++ {
		if x.Response.Response.Objects[i].ExpiryStatus == "Expired" {
			// return early if an expired certificate is found
			return x.Response.Response.Objects[i].ResourceID, x.Response.Response.Objects[i].SerialNumber, true, 995, nil
		}
	}
	// if only expired or revoked certificates are found, return 404, so that new certificate will be created
	return "", "", false, 0, fmt.Errorf("certificate search is failing for common name %s with status %d", cn, resp.StatusCode)
}

func APICertificateHandler(spec *v1alpha1.ClusterIssuerSpec, token string, csr string, cn string, interCert string) ([]byte, error) {
	resourceID, serialNumber, exists, ccode, err := SearchCertificate(spec, token, cn)
	if err == nil {
		if exists && ccode == 200 && resourceID != "" {
			// handling a single valid certificate
			//revoking the certificate based on resource ID
			rcode, err := RevokeCertificate(spec, token, cn, resourceID)
			if err != nil || rcode != 200 {
				return nil, err
			}
			certificate, crcode, err := CreateCertificate(spec, token, csr, cn, interCert)
			if crcode != 200 || err != nil {
				return nil, fmt.Errorf("failed to create a new certificate for common name %s with status code %d", cn, crcode)
			}
			// logic for delete
			dcode, err := DeleteCertificate(spec, token, cn, serialNumber)
			if err != nil || dcode != 200 {
				return nil, fmt.Errorf("failed to delete the certificate for common name %s and serial number %s", cn, serialNumber)
			}
			return certificate, nil
		}
		if exists && ccode == 995 && resourceID != "" {
			// handling expired certificate
			//revoking the certificate based on resource ID
			rcode, err := RevokeCertificate(spec, token, cn, resourceID)
			if err != nil || rcode != 200 {
				return nil, err
			}
			certificate, crcode, err := CreateCertificate(spec, token, csr, cn, interCert)
			if crcode != 200 || err != nil {
				return nil, fmt.Errorf("failed to create a new certificate for common name %s with status code %d", cn, crcode)
			}
			// logic for delete
			dcode, err := DeleteCertificate(spec, token, cn, serialNumber)
			if err != nil || dcode != 200 {
				return nil, fmt.Errorf("failed to delete the certificate for common name %s and serial number %s", cn, serialNumber)
			}
			return certificate, nil
		}
		if !exists && ccode == 404 {
			//Certificate not found
			certificate, crcode, err := CreateCertificate(spec, token, csr, cn, interCert)
			if crcode != 200 || err != nil {
				return nil, fmt.Errorf("failed to create a new certificate for common name %s with status code %d", cn, crcode)
			}
			return certificate, nil
		}
		if exists && ccode == 996 {
			certificate, crcode, err := CreateCertificate(spec, token, csr, cn, interCert)
			if crcode != 200 || err != nil {
				return nil, fmt.Errorf("failed to create a new certificate for common name %s with status code %d", cn, crcode)
			}
			return certificate, nil
		}
		if exists && ccode == 997 {
			return nil, fmt.Errorf("some certficates are waiting to be approved manually for common name %s", cn)
		}
		if exists && ccode == 998 {
			return nil, fmt.Errorf("multiple valid/soon to expire certificates are found for common name %s", cn)
		}
	}
	return nil, fmt.Errorf("unable to handle the certificate request for common name %s", cn)
}

func CreateCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, csr string, cn string, interCert string) (certificate []byte, code int, err error) {
	aurl := spec.URL
	nurl := aurl + "/certificate/create?gwsource=external&isSync=true&ttl=300"
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return nil, 0, err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	var ndata *strings.Reader
	if strings.Contains(aurl, "non-prod") {
		ndata = strings.NewReader(fmt.Sprintf(`{
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
	} else {
		ndata = strings.NewReader(fmt.Sprintf(`{
			"csrGenerationSource": "uploadCSR",
			"caConnectorInfo": {
				"certificateAuthority": "Microsoft Enterprise",
				"isAutoRenewal": false,
				"autoRegenerateEnabled": false,
				"caSettingName": "SparkProdCA03",
				"vendorSpecificDetails": {
					"templateName": "SparkTLSServerAuth"
				}
			},
			"uploadCsrDetails": {
				"csrContent": "%v",
				"category": "Server"
			},
			"certificateGroup": {
				"name": "CG_Internal_Openshift"
			},
			"certificateFormat": {
				"format": "PEM",
				"password": ""
			}
		}`, csr))
	}
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
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != 200 || resp == nil {
		return nil, 0, fmt.Errorf("certificate creation request is failing for common name %s with status code %d, message body %s", cn, resp.StatusCode, string(bodyText))
	}
	var x CreationResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return nil, 0, err
	}
	origCert, err := base64.StdEncoding.DecodeString(x.Response.CertificateContent)
	if err != nil {
		return nil, 0, err
	}
	strCert := string(origCert) + interCert
	if strCert != "" {
		return []byte(strCert), resp.StatusCode, nil
	}
	return nil, 0, fmt.Errorf("unable to create certificate for common name %s", cn)
}

func RevokeCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, cn string, resourceid string) (code int, err error) {
	aurl := spec.URL
	nurl := aurl + "/certificate/revoke?gwsource=external&isSync=true&ttl=300"
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return 0, err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   50 * time.Second,
		Transport: tr,
	}
	var data = strings.NewReader(fmt.Sprintf(`{"resourceId": "%s","reason": "Superseded"}`, resourceid))
	req, err := http.NewRequest("PUT", nurl, data)
	if err != nil {
		return 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 || resp == nil {
		return resp.StatusCode, fmt.Errorf("certificate revoke request is failing for resource ID %s with status code %d, message body %s", resourceid, resp.StatusCode, string(bodyText))
	}
	var x RevokeResponse
	err = json.Unmarshal([]byte(bodyText), &x)
	if err != nil {
		return 0, err
	}
	if x.AppStatusCode == "SUCCESS" && x.Response.CertStatus == "Revoked" && x.Response.ResourceID == resourceid {
		return 200, nil
	}
	return 0, fmt.Errorf("unable to revoke the certificate for common name %s", cn)
}

func DeleteCertificate(spec *v1alpha1.ClusterIssuerSpec, token string, cn string, serialNumber string) (code int, err error) {
	aurl := spec.URL
	nurl := aurl + fmt.Sprintf("/certificate/delete?gwsource=external&commonName=%s&serialNumber=%s", cn, serialNumber)
	var tr *http.Transport
	if spec.Proxy != "" {
		purl, err := url.Parse(spec.Proxy)
		if err != nil {
			return 0, err
		}
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(purl),
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client := &http.Client{
		Timeout:   50 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest("DELETE", nurl, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 || resp == nil {
		return resp.StatusCode, fmt.Errorf("certificate delete request is failing for common name %s with serial number %s, message body %s", cn, serialNumber, string(bodyText))
	}
	return resp.StatusCode, nil
}
