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
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k8s.io/client-go/tools/clientcmd"
)

// Cluster holds the cluster data
type Cluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

//Clusters hold an array of the clusters that would exist in the config file
type Clusters []struct {
	Cluster Cluster `yaml:"cluster"`
	Name    string  `yaml:"name"`
}

//Context holds the cluster context
type Context struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

//Contexts holds an array of the contexts
type Contexts []struct {
	Context Context `yaml:"context"`
	Name    string  `yaml:"name"`
}

//Users holds an array of the users that would exist in the config file
type Users []struct {
	User User   `yaml:"user"`
	Name string `yaml:"name"`
}

//User holds the user authentication data
type User struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

//KubeConfig holds the necessary data for creating a new KubeConfig file
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
func check(msg string, err error) {
	if err != nil {
		log.Fatal(fmt.Sprintf("%s: %s", msg, err))
	}
}
func main() {
	usernamePtr := flag.String("username", "", "[Required] The username")
	emailPtr := flag.String("email", "", "[Required] The user's email")
	clusterPtr := flag.String("cluster", "", "[Required] The cluster's name")
	countryPtr := flag.String("country", "", "[Optional] The user's country")
	cityPtr := flag.String("city", "", "[Optional] The user's city")
	orgazniationPtr := flag.String("orgazniation", "", "[Optional] The user's orgazniation")
	orgUnitPtr := flag.String("orgUnit", "", "[Optional] The user's organizational unit")
	provincePtr := flag.String("province", "", "[Optional] The user's province")
	flag.Usage = func() {
		flagSet := flag.CommandLine
		fmt.Printf("Usage: %s [Requied flags] [Optional flags] \n", path.Base(os.Args[0]))
		order := []string{"username", "email", "cluster", "country", "city", "orgazniation", "orgUnit", "province"}
		for _, name := range order {
			flag := flagSet.Lookup(name)
			fmt.Printf("--%s\n", flag.Name)
			fmt.Printf("  %s\n", flag.Usage)
		}
		os.Exit(2)
	}
	flag.Parse()
	if *usernamePtr == "" {
		fmt.Println("The username is required")
		flag.Usage()
	}
	if *emailPtr == "" {
		fmt.Println("The user's email is required")
		flag.Usage()
	}
	if *clusterPtr == "" {
		fmt.Println("The cluster name is required")
		flag.Usage()
	}
	if *countryPtr != "" && len(*countryPtr) > 2 {
		log.Fatal("Invalid country. The name must be two letters. Example: US, AU, EG")
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	check("The following error occured while creating the RSA key", err)
	keyDer := x509.MarshalPKCS1PrivateKey(key)
	commonName := *usernamePtr
	emailAddress := *emailPtr
	org := strings.ToUpper(*orgazniationPtr)
	orgUnit := strings.ToUpper(*orgUnitPtr)
	city := strings.ToUpper(*cityPtr)
	state := strings.ToUpper(*provincePtr)
	country := strings.ToUpper(*countryPtr)
	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Locality:           []string{city},
		Organization:       []string{org},
		OrganizationalUnit: []string{orgUnit},
		Province:           []string{state},
	}
	asn1, err := asn1.Marshal(subject.ToRDNSequence())
	check("The following error occured while creating the asn1 DNS sequence", err)
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
	check("The following error occured while getting the Kube Config file", err)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	clientset, err := kubernetes.NewForConfig(config)
	check("The following error occured while loading the Kube Config file", err)
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: "tempcsr",
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups: []string{
				"system:authenticated",
			},
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes}),
		},
	}
	_, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Create(context.TODO(), csr, v1.CreateOptions{})
	check("The following error occured while sending the Certificate Signing Request", err)
	csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:           certificates.CertificateApproved,
		Reason:         "User activation",
		Message:        "This CSR was approved",
		LastUpdateTime: v1.Now(),
	})
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(context.Background(), csr, v1.UpdateOptions{})
	check("The following error occured while approving the Certificate Signing Request", err)
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Get(context.TODO(), csr.GetName(), v1.GetOptions{})
	clientset.CertificatesV1beta1().CertificateSigningRequests().Delete(context.TODO(), csr.GetName(), v1.DeleteOptions{})
	kubeConfig, err := clientcmd.LoadFromFile(kubeconfig)
	check("The following error occured while loading the KubeConfig file", err)
	if _, v := kubeConfig.Clusters[*clusterPtr]; !v {
		log.Fatal(fmt.Sprintf("Cluster \"%s\" was not found in the current Kube Config file", *clusterPtr))
	}
	kc := &KubeConfig{
		APIVersion: "v1",
		Clusters: Clusters{
			0: {
				Cluster{
					base64.StdEncoding.EncodeToString([]byte(kubeConfig.Clusters[*clusterPtr].CertificateAuthorityData)),
					kubeConfig.Clusters[*clusterPtr].Server,
				},
				*clusterPtr,
			},
		},
		Contexts: Contexts{
			0: {
				Context{
					Cluster: *clusterPtr,
					User:    *usernamePtr,
				},
				*clusterPtr,
			},
		},
		CurrentContext: *clusterPtr,
		Kind:           "Config",
		Users: Users{
			0: {
				User{
					ClientCertificateData: base64.StdEncoding.EncodeToString(csr.Status.Certificate),
					ClientKeyData:         base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer})),
				},
				*usernamePtr,
			},
		},
	}
	dir, err := os.Getwd()
	check("The following error occured while getting the current working directory %s", err)
	_, err = os.Create(filepath.Join(dir, *usernamePtr))
	check("The following error occured while creating the target file %s", err)
	file, err := os.OpenFile(*usernamePtr, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	check("The following error occured while creating the target Kube Config file", err)
	defer file.Close()
	e := yaml.NewEncoder(file)
	err = e.Encode(kc)
	check("The following error occured while writing YAML to the target Kube Config file", err)
}
