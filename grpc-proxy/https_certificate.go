package grpc_proxy

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	cpkix "crypto/x509/pkix"

	"github.com/ssoor/certstrap/pkix"
)

const (
	CARootCert string = `-----BEGIN CERTIFICATE-----
MIIJzzCCBbegAwIBAgIJAO0GVOaT5NSZMA0GCSqGSIb3DQEBCwUAMH0xCzAJBgNV
BAYTAkNOMR4wHAYDVQQKDBVZb3VuaXZlcnNlIFJlZGVtcHRpb24xITAfBgNVBAsM
GFlvdW5pdmVyc2UgVHJ1c3QgTmV0d29yazErMCkGA1UEAwwiWW91bml2ZXJzZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAgFw0xNjA2MTcwNDIzMzVaGA8yMjkwMDQw
MTA0MjMzNVowfTELMAkGA1UEBhMCQ04xHjAcBgNVBAoMFVlvdW5pdmVyc2UgUmVk
ZW1wdGlvbjEhMB8GA1UECwwYWW91bml2ZXJzZSBUcnVzdCBOZXR3b3JrMSswKQYD
VQQDDCJZb3VuaXZlcnNlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIEIjANBgkq
hkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA1fIQFokp99nag8kjQzO4wtVhV9OBVXCV
YeRmJ/3DFlJ2Av1kzd+7OsDdZc+rkP0e2fyO6hapZm/V/su0PittSkyaNtbdhQI5
W9FCXhvIU4w6jPkIDFXWsyjQcfy5YkXI7NpXn2yvYQWlzzGHYtZqUQNIEk6bQwiJ
COBUFqjkY0xCUyXeL4K1vhjUQ9ucbjTCRN0QUoqps0p9HtUsC09Q5YHoT0R4wQLi
CbqWJco9xMS8ZG73EMvnMnCxj4pqfWXhNDUQ8TkMxn9+Q/Qlv5jSJXcmk1evG9sr
mxjIR7GGft1YZzO/WR3aDHdHVic+Dlk+EgUjuaQ535QWfw53nM0EfLPMfZOROwx9
2CecNwbv0rFPZE745w3rSZCnxQzk9brZEpizmD0syZTqFHyDRST7JxRaJffIqF45
wE2gTh0rAqKSH1d4Fy3YpKSTT2DYpNPS3UhF7u3CPIHagS5DU9cCmzGBMy4bSfUN
mJMTfzLFuj0USXeBOntcT/Esv6k+ME6x8gveKuRlqdd0qFjen9n9Ds328UstyN01
l5CdwnOBN9L3sR0RsQwKVyw/bLtHz4DKEfcbxQYP2MH1/7cuRqxQ4HZahYTq38lX
HG+qgZBcK1ULgWZ5+yHE/8HTvWVncjyuGiWIf2PHbVpir+mu7t+w22H1tv0zujPw
0wTp3fQacydG1Dr/QqoZYagg3Xjz3juFHR/YA3rf33yd21bmMc4HPl6MLXM9x/WU
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
GGaY57BOarhwIsosw44WeKGhSA==
-----END CERTIFICATE-----`
	CAIntermediateKey string = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	CAIntermediateCert string = `-----BEGIN CERTIFICATE-----
MIIJtDCCBZygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwfTELMAkGA1UEBhMCQ04x
HjAcBgNVBAoMFVlvdW5pdmVyc2UgUmVkZW1wdGlvbjEhMB8GA1UECwwYWW91bml2
ZXJzZSBUcnVzdCBOZXR3b3JrMSswKQYDVQQDDCJZb3VuaXZlcnNlIENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MCAXDTE2MDYxNzA0MjMzN1oYDzIyOTAwNDAxMDQyMzM3
WjCBkzExMC8GA1UEAwwoWW91bml2ZXJzZSBDbGFzcyAzIFNlY3VyZSBTZXJ2ZXIg
Q0EgLSBHNDEOMAwGA1UECAwFQ2hpbmExCzAJBgNVBAYTAkNOMR4wHAYDVQQKDBVZ
b3VuaXZlcnNlIFJlZGVtcHRpb24xITAfBgNVBAsMGFlvdW5pdmVyc2UgVHJ1c3Qg
TmV0d29yazCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALnL76W2RxHr
rewta6A1lbgZdC5sTU0NIP6VsU+ubR6cOmFspgK27xv8Bz+EJuS/w0alDdeDX4Zk
+M+WCUX8Z0x9BhDdg+9Y7xzDSEfxc9sdViMxg6udwCqi5TyBYi19DTlRFrpXy8Do
Lg+zYRpetdToXGKSZXdSzVm+UNd3ZQ16aB1CJ2HJ+695GEhZ1udFpbHfoPQC+UUT
2jqEc8xrrQ/4hE1jnSUggCnoWPnsMs1l+oBZg+cZ2vINnaXCxKxP70Qmuz6a9hdK
EMUTV2UI7JiL1N/+qh/hglRbBQZ70neQo9fenyNu2SIThe5fqN0dI1XcDDnKgF19
bhcU1YISsND1GKIEwGy0IGf+HpZBB7W6KQuKaUuEzGMD7ePEGlg3VrE1Um0QbiPq
lWhdXkRhNK6MOatqLuNJLhVvW8CAKlyy2DHoV/KnN1wJcEHiZNAoFzw0ge/hCNSJ
cPcvBdJ2q4Tj8Hh6ynlxrcvoY70OoFa9HMTMv4fuSesgqBo28G/yz6X0VjGsnk9f
/EC0Eh99K6PmldFPMrG748lF87TyNmiXkGHyhED5QIcXMhaJeYO10OPfqzomPoGD
qexhIIH2h9YTmbrgOtDMgcyCkMDxesGFyw3ilCgGUKofgG5demigOwbCgvIS2nVO
tQYUFSaf7Psyg50nVRjGI1Y5QpM2UN5fAgMBAAGjggIjMIICHzAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBT0500pn0eVX+/6c/Sihq3SnsOtvTAfBgNVHSMEGDAW
gBTZiJoYu+/UgTqQnpwPDBrzHm1sbTALBgNVHQ8EBAMCAaYwEwYDVR0lBAwwCgYI
KwYBBQUHAwEwMwYDVR0RBCwwKoIoWW91bml2ZXJzZSBDbGFzcyAzIFNlY3VyZSBT
ZXJ2ZXIgQ0EgLSBHNDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL3d3dy55b3Vu
aXZlcnNlLmNvbS9Zb3VuaXZlcnNlSW50ZXJtaWRpYXRlLmNybDA6oDigNoY0aHR0
cDovL3d3dy55b3VuaXZlcnNlLmNvbS9Zb3VuaXZlcnNlSW50ZXJtaWRpYXRlLmNy
bDCB8AYIKwYBBQUHAQEEgeMwgeAwQQYIKwYBBQUHMAKGNWh0dHA6Ly93d3cueW91
bml2ZXJzZS5jb20vWW91bml2ZXJzZUludGVybWVkaWF0ZTEuY3J0MEEGCCsGAQUF
BzAChjVodHRwOi8vd3d3LnlvdW5pdmVyc2UuY29tL1lvdW5pdmVyc2VJbnRlcm1l
ZGlhdGUxLmNydDArBggrBgEFBQcwAYYfaHR0cDovL3d3dy55b3VuaXZlcnNlLmNv
bS9vY3NwLzArBggrBgEFBQcwAYYfaHR0cDovL3d3dy55b3VuaXZlcnNlLmNvbS9v
Y3NwLzANBgkqhkiG9w0BAQsFAAOCBAEAQF0NkcuGpJngLCUTs1JHnlhV9bEzzcJ8
oMUYM5gEMrZ+C1o/q+Dr3p3wYa0BKazy2zxOPlCmzsh6m8K9vonTTjA5SBqiCk9D
op0A8wxwq2B4KxE0sVK4McBkyQ7LRc8A8oWCsoNSWlWkYMXDeLuESl+0hLvjqwfJ
pvOxezdQy4C/AQTlHWegDMWGqiqsyFUc9sx9ueTJFkAnseeCQXZOCd5TGSgDmR7b
7W+OGMWd66vPLe+e/Z07VMHFLDMa4s355X8fU3Uj7frBdUB3DUYTi79zz7So4uJY
qssE+GH2uogNy8fv+xtr/q3zW7696SdXMFyuq652HI49YQ8zsRCtadAbxzIScvvy
bi9O/pqDyw48hX5zHgzvMHAoTEYPCJAfRV+sbJBiM/oNPZ3M5RnMyT4sIib0VQYq
uNjyWuvYHiFcHRUhdTHZZvcQVRWzY9yFoQv/t3BFR4T90jhAiNxRBJKCgIKIrMDi
4LCdEUspSBOWmppJFypXn19QzpFDtdF96PZynN0pFQlWQJ+3atJ1YW9zIFMVSzJw
U+KK1pB3Ujj49ohMakCoHrgVj8X2N8K1dKIiviV4rc/Ap5q+g2MR6Z8hutcfgTEo
D0mrNFmetZwleauFp9hRlLZXde0SREeOiJmz8pUrq3YMtY+iCnkiB1qMWZ9RpcVv
+yPaX23tajbMK6id9f2SKAd020WTkZqrSVnfuz9kJaQCPi0GDl4J3RdPQ90vqYal
pCdLOfqiVYHD0fUMqzSKfujkyUrjjyItapbiMLsEJetA+xQf2SbWGvJ5QXyyoJVT
WCKdYue8vmF04qyapV35zPiBkI2dXZq6B9MRZ1ecRvwy9ZBnBhMapcdvHyUv+V/8
ZC+P66Awsgo1x/P1hT/BzUpqOpSWSEewvU62wl/TWrFz5KkRYJQ2iPFQoBDwSvvc
mPpRbpyTVjQIZadUXK/U0C05Wfx8Du2BVNpdSINM0P9Zr4UJvjKmZ2EK+JobbFYr
IieF0mHAteh3ala3CuQVk7mZCyRviNjH1AusgcQINPoQkWjDFbcKo6esYaGqIHvk
bKO782hzKNN2YqRO2oui8n/GFYnnvlh721ybsFg8tZouUTxD7DMngivmFBWUxwWF
XFvXyc156zWY7uLrlHVXT4toxkYKEzuebnK/LlGVtI0OeO2Z3Pmdv8l367bnnz/M
TbyFCMW2hIwfXMRpPnWlp90I50/J/6Rf8bpSOr788AEQ1I9BZpBsCXczfU6ojGD3
8XcJsltNSKkRcs43DxFtGzuByJ8w5WpgCvMsUt5r4wpS1K/VsSV/Kuzr9k1fHhbn
w9eZGdAOcXT8zniIa5tIpP9maJA65wQjdjUiwYiIaXRAf6DjK886nA==
-----END CERTIFICATE-----`
)

type certKeyPair struct {
	cert *pkix.Certificate
	key  *pkix.Key
}

func (p *certKeyPair) toX509Pair() tls.Certificate {
	cb, err := p.cert.Export()
	if err != nil {
		log.Fatalln("Export cert failed:", err)
	}
	kb, err := p.key.ExportPrivate()
	if err != nil {
		log.Fatalln("Export private failed:", err)
	}
	cert, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		log.Fatalln("Make X509 KeyPair failed:", err)
	}
	return cert
}

func QueryTlsCertificate(host string) (tlsCert *tls.Certificate, err error) {
	v, exists := tlsCerts.Load(host)
	if exists {
		cert := v.(tls.Certificate)
		return &cert, nil
	}
	return nil, errors.New("not find certificate")
}

var (
	tlsCertsKey *pkix.Key
	tlsCerts    sync.Map
)

func GetCAIntermediatePair() (certPair *certKeyPair, err error) {
	var key *pkix.Key
	var cert *pkix.Certificate

	if key, err = pkix.NewKeyFromPrivateKeyPEM([]byte(CAIntermediateKey)); nil != err {
		return nil, err
	}

	if cert, err = pkix.NewCertificateFromPEM([]byte(CAIntermediateCert)); nil != err {
		return nil, err
	}

	return &certKeyPair{cert: cert, key: key}, nil
}

var (
	// Build CA based on RFC5280
	hostTemplate = x509.Certificate{
		// **SHOULD** be filled in a unique number
		SerialNumber: big.NewInt(0),
		// **SHOULD** be filled in host info
		Subject: cpkix.Name{},
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore: time.Now().Add(-600 * time.Second).UTC(),
		// 10-year lease
		NotAfter: time.Time{},
		// Used for certificate signing only
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		UnknownExtKeyUsage: nil,

		BasicConstraintsValid: false,

		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		// **SHOULD** be filled in later
		SubjectKeyId: nil,

		// Subject Alternative Name
		DNSNames: nil,

		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}
)

// CreateCertificateHost creates certificate for host.
// The arguments include CA certificate, CA key, certificate request.
func CreateCertificateHost(crtAuth *pkix.Certificate, keyAuth *pkix.Key, csr *pkix.CertificateSigningRequest, years int) (*pkix.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	hostTemplate.SerialNumber.Set(serialNumber)

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		return nil, err
	}

	hostTemplate.Subject = rawCsr.Subject

	caExpiry := time.Now().Add(crtAuth.GetExpirationDuration())
	proposedExpiry := time.Now().AddDate(years, 0, 0).UTC()
	// ensure cert doesn't expire after issuer
	if caExpiry.Before(proposedExpiry) {
		hostTemplate.NotAfter = caExpiry
	} else {
		hostTemplate.NotAfter = proposedExpiry
	}

	hostTemplate.SubjectKeyId, err = pkix.GenerateSubjectKeyID(rawCsr.PublicKey)
	if err != nil {
		return nil, err
	}

	hostTemplate.IPAddresses = rawCsr.IPAddresses
	hostTemplate.DNSNames = rawCsr.DNSNames

	rawCrtAuth, err := crtAuth.GetRawCertificate()
	if err != nil {
		return nil, err
	}

	crtHostBytes, err := x509.CreateCertificate(rand.Reader, &hostTemplate, rawCrtAuth, rawCsr.PublicKey, keyAuth.Private)
	if err != nil {
		return nil, err
	}

	return pkix.NewCertificateFromDER(crtHostBytes), nil
}

func CreateTlsCertificate(key *pkix.Key, host string, startTimeOffset time.Duration, years int) (tlsCert *tls.Certificate, err error) {
	var cert *pkix.Certificate

	if nil == key {
		if tlsCertsKey, err = pkix.CreateRSAKey(1024); err != nil {
			log.Println("Create RSA key failed:", err)
			return nil, err
		}

		key = tlsCertsKey
	}

	csr, err := pkix.CreateCertificateSigningRequest(key, "Youniverse Trust Network", nil, []string{host}, "Youniverse Redemption", "CN", "China", "Beijing", host)
	if err != nil {
		log.Println("Create CSR failed:", err)
		return nil, err
	}
	var certPair *certKeyPair
	if certPair, err = GetCAIntermediatePair(); nil != err {
		log.Println("Get CA Intermediate failed:", err)
		return nil, err
	}

	if cert, err = CreateCertificateHost(certPair.cert, certPair.key, csr, years); err != nil {
		log.Println("Create cert failed:", err)
		return nil, err
	}

	certPair.key = key
	certPair.cert = cert
	certx509Pair := certPair.toX509Pair()
	tlsCerts.Store(host, certx509Pair)
	return &certx509Pair, nil
}
