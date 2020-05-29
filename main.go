package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	name := os.Args[1]
	user := os.Args[2]
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	keyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDer,
	}
	keyFile, err := os.Create(name + "_key.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(keyFile, &keyBlock)
	keyFile.Close()
	commonName := user
	emailAddress := "user@domain.com"
	org := "My company"
	orgUnit := "My unit"
	city := "Seattle"
	state := "WA"
	country := "US"
	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Locality:           []string{city},
		Organization:       []string{org},
		OrganizationalUnit: []string{orgUnit},
		Province:           []string{state},
	}
	asn1, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		panic(err)
	}
	csrReq := x509.CertificateRequest{
		RawSubject:         asn1,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	bytes, err := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
	if err != nil {
		panic(err)
	}
	csrFile, err := os.Create(name + ".csr")
	if err != nil {
		panic(err)
	}
	pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes})
	csrFile.Close()
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "sjstaging")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: "mycsr4",
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups: []string{
				"system:authenticated",
			},
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes}),
		},
	}
	_, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Create(context.TODO(), csr, v1.CreateOptions{})
	if err != nil {
		fmt.Println(err)
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:           certificates.CertificateApproved,
		Reason:         "BLABLABLA",
		Message:        "This CSR was approved by BLABLABLA",
		LastUpdateTime: v1.Now(),
	})
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(context.TODO(), csr, v1.UpdateOptions{})
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(csr.Status.Certificate))
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type:  "RSA PRIVATE KEY",Bytes: keyDer,})))
	}
	clientset.CertificatesV1beta1().CertificateSigningRequests().Delete(context.TODO(),csr.GetName(),v1.DeleteOptions{})
}
