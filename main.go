package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/client-go/tools/clientcmd"
)

type Cluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}
type Clusters []struct {
	Cluster Cluster `yaml:"cluster"`
	Name    string  `yaml:"name"`
}
type Context struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}
type Contexts struct {
	Context Context `yaml:"context"`
	Name    string  `yaml:"name"`
}
type Users []struct {
	User User   `yaml:"user`
	Name string `yaml:"name"`
}
type User struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}
type KubeConfig struct {
	APIVersion     string   `yaml:"apiVersion"`
	Clusters       Clusters `yaml:"clusters"`
	Contexts       Contexts `yaml:"contexts"`
	CurrentContext string   `yaml:"current-context"`
	Kind           string   `yaml:"kind"`
	Preferences    struct{} `yaml:"preferences"`
	Users          Users    `yaml:"users"`
}

func findKubeConfig() (string, error) {
	env := os.Getenv("KUBECONFIG")
	if env != "" {
		return env, nil
	}
	path, err := homedir.Expand("~/.kube/config")
	if err != nil {
		return "", err
	}
	return path, nil
}

func main() {
	username := os.Args[1]
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	commonName := username
	emailAddress := ""
	org := ""
	orgUnit := ""
	city := ""
	state := ""
	country := ""
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
	kubeconfig, err := findKubeConfig()
	if err != nil {
		panic(fmt.Sprintf("An error occured while getting the KubeConfig file: %v", err))
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: "tempscr",
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
		Reason:         "User activation",
		Message:        "This CSR was approved",
		LastUpdateTime: v1.Now(),
	})
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(context.Background(), csr, v1.UpdateOptions{})
	if err != nil {
		fmt.Println(err)
	}
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Get(context.TODO(), csr.GetName(), v1.GetOptions{})
	clientset.CertificatesV1beta1().CertificateSigningRequests().Delete(context.TODO(), csr.GetName(), v1.DeleteOptions{})
	kubeConfig, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		log.Fatal(err)
	}
	kc := &KubeConfig{
		APIVersion: "v1",
		Clusters: Clusters{
			0: {
				Cluster{
					base64.StdEncoding.EncodeToString([]byte(kubeConfig.Clusters["disney.demo.k8s.local"].CertificateAuthorityData)),
					kubeConfig.Clusters["disney.demo.k8s.local"].Server,
				},
				"disney.demo.k8s.local",
			},
		},
		Contexts: Contexts{
			Context{
				Cluster: "disney.demo.k8s.local",
				User:    username,
			},
			"disney.demo.k8s.local",
		},
		CurrentContext: "disney.demo.k8s.local",
		Kind:           "Config",
		Users: Users{
			0: {
				User{
					ClientCertificateData: base64.StdEncoding.EncodeToString(csr.Status.Certificate),
					ClientKeyData:         base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer})),
				},
				username,
			},
		},
	}
	os.Create(username)
	file, err := os.OpenFile(username, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		panic(fmt.Sprintf("An error occured while creating the target KubeConfig file: %v", err))
	}
	defer file.Close()
	e := yaml.NewEncoder(file)
	e.Encode(kc)
}
