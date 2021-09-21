# Kubernetes Automatic User Creator

The purpose of this tool is to automate the process of generating Certificate Signing Request, sending it to the API server, approving and downloading the certificate. The program generates the necessary Kube Config file that contains the user certificate and key. This file can then be handed to the user to use for authentication. The program uses the current Kube Config file, either `~/.kube/config` or the one defined in the `KUBECONFIG` environment variable.

## Usage:

```bash
./k8suser --username myuser --email myuseremail --cluster clusername --country US --city IL --organization acmecorp --orgUnit DevOps --province Chicago
```

The command-line option can be explained as follows:
`--outdir`: The directory where you want the generated KUBECONFIG to be placed (defaults to the current working diectory)
`--username`: The name used for authentication (Required)

`--email`: The user's email (Required)

`--cluser`: The name of the cluster (Required). The program uses this name to extract the relevent information from the Kube Config file

`--country`: Optional

`--city`: Optional

`--organization`: Optional

`--orgUnit`: Optional

`--province`: Optional

## How to use

You must have Go version 1.14 or higher. Clone the repository, build the program and execute it with the above options. For example:

```bash
git clone https://github.com/abohmeed/k8susercreator
cd k8susercreator
go build ./...
./k8suser 
```





