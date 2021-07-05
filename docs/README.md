

# EdgeCA
**EdgeCA** is an ephemeral, in-memory CA providing service mesh machine identities.
It automates the management and issuance of TLS certificates. It can either run with a self-certificated Root CA certificate or use an issuing certificate retrieved using the [Venefi vCert](https://github.com/Venafi/vcert) software.

It solves the many limitations of the embedded service mesh CAs by providing developers a fast, easy, and integrated source of machine identities whilst also providing security teams with the required policy and oversight.  

It also enables ephemeral certificate-based authorization, which reduces the need for permanent access credentials, explicit access revocation or traditional SSH key management. 

EdgeCA is meant for evaluation only. 

 
### Installing using snaps

The easiest way to install EdgeCA on Ubuntu is to use snaps. Simply do:

```
snap install edgeca
```
See the [EdgeCA Snap install](../snap) readme file for more information. **Note** that if you are using snaps, then **edgecad** runs as a background service and you need not start it manually.

### Installing using docker

To get the edgeca docker image do

```
docker pull edgesec/edgeca
```

To run a sample server locally in a docker container, you can do

```
docker run -p 0.0.0.0:50025:50025 -h localhost -v ~/.edgeca/certs:/shared-secrets edgesec/edgeca server -d /shared-secrets
```

Note that this tells edgeca to write the secrets required for the secure gRPC connection to a /shared-secrets directory, which is redirected to
your local ~/.edgeca/certs directory. It also sets the host name to "localhost", so that the generated TLS certificate for gRPC will be issued for "localhost"


You can then run the edgeca client locally. Set it to connect to "localhost". It will pick up the TLS gRPC certificates from the default ~/.edgeca/certs location

```
./bin/edgeca gencert -i csrfile --server localhost
```



## Compiling edgeca

To install from the Go source do:

```
git clone https://github.com/edgesec-org/edgeca.git
cd edgeca
go install ./cmd/edgeca
```

## Using WebAssembly
It's possible to compile EdgeCA to a WebAssembly. See the [edgeca-webassembly](https://github.com/edgesec-org/edgeca-webassembly) repository. 



## Start up **EdgeCA server**
**edgeca** is the command line interface (CLI) application you will use to create CSRs and certificates. It can generate CSRs independently, but to sign certificates, it requires an EdgeCA server to perform the certificate signing. to start EdgeCA in server mode, run `edgeca server` to start up a server which edgeca connects to. It is the core Ephemeral CA engine and signs the certificates. Note that the snap does this automatically, running a server as a background daemon process. 

To get help, type
```
edgeca server -h
```

The output will show:

```
EdgeCA can run in three modes
	
	Mode 1: Self-signed
	-------------------
	./edgecad [-p policy_file]
	
	In this mode, EdgeCA starts up, creates a self-signed certificate 
	and optionally reads in an OPA policy file. 
	
	Mode 2:  Bring your own CA Certificate
	--------------------------
	./edgecad [-p policy_file] -c certificate.pem -k key.pem
	
	In this mode, EdgeCA starts up, reads the CA certificate and key
	from the provided PEM files and optionally reads in an OPA policy file 
		
	Mode 3: Use TPP
	-------------------------------
	./edgecad --url "..." --zone "..." --token "..." 
	
	EdgeCA gets an issuing certificate using the TPP token.
	It reads in the policy and default configuration from the TPP server 

Note: In all three modes, the server writes certificates to the location
specified by "tls-certs". These certificates are required by the edgeca client
for encryption and authentication.

Usage:
  edgecad [flags]

Flags:
  -c, --ca-cert string     Issuing Certificate File
  -k, --ca-key string      Issuing Certificate Key File
  -h, --help               help for edgecad
  -p, --policy string      Policy File
      --port int           Port number to use for this server (default 50025)
  -d, --tls-certs string   Directory to write gRPC TLS Client certificates to (default "/home/sidar/.edgeca/certs")
  -t, --token string       TPP Token
  -u, --url string         TPP URL
  -z, --zone string        TPP Zone

```

### Mode 1: Self-signed

Start by running edgeca in a terminal window. The simplest setup is to use a self-signed certificate. All you need then to do is to type

```
edgeca server
```

EdgeCA will then start up 
```
EdgeCA server 0.3.0 starting up
edgeCA: 2021/01/19 16:24:16 Mode 1 (Using self-signed issuing certificate and key)
edgeCA: 2021/01/19 16:24:16 Generating self signed Root CA Certificate
edgeCA: 2021/01/19 16:24:16 Generating self signed Sub CA Certificate
edgeCA: 2021/01/19 16:24:16 Creating TLS server certificate for server
edgeCA: 2021/01/19 16:24:17 Writing TLS Client certificate to /home/me/.edgeca/certs/edgeca-client-cert.pem
edgeCA: 2021/01/19 16:24:17 Writing TLS Client key to /home/me/.edgeca/certs/edgeca-client-key.pem
edgeCA: 2021/01/19 16:24:17 Writing Root CA Certificate to  /home/me/.edgeca/certs/CA.pem
edgeCA: 2021/01/19 16:24:17 Starting gRPC CA server on port 50025
```

There are some optional parameters which you can use
- **--port** is used to specify the TCP/IP port to listen on. By defult EdgeCA uses 50025
- **--tls-certs** is used to specify where to write the certificates which are generated by EdgeCA for the TLS connection between EdgeCA server and client. These certificates need to be accessible by the client. By default both server and client use ~/.edgeca/certs but if you run the server and client on two different devices, then the certificates need to be copied to where they can be accessed by the client
- **--policy** can be used to Specify an [Open Policy Agent](https://www.openpolicyagent.org/) policy file. The policy should be in the "edgeca" package and be named "csr_policy". A sample file would be:

### (Optional) Using policies

Example file:

```
package edgeca

	csr_policy {

        re_match(`^ACME inc$`, input.csr.Subject.Organization[0])
 
    }

```

EdgeCA will transform Venafi TPP policies into OPA policies so if you are using TPP and have a policy defined, the edgecad will print out the OPA policy it generated. 

To use a manually generated policy file, specify it using the **-p** parameter 

```
edgeca server -p opa/opa.rego
```

### Mode 3: Use TPP

EdgeCA can integrate with a [Venafi](https://www.venafi.com) backend, using [Venafi VCert](https://www.github.com/Venafi/vcert). To use that, do the following:

You should have a TPP URL,  Zone, username and password. First use VCert to generate a TPP token:

```
git clone https://github.com/Venafi/vcert.git
cd vcert
make build
./bin/linux/vcert getcred -u YOUR_URL --username your_USERNAME --password YOUR_PASSWORD --client-id=edgeca

```

then use the generated token to start up EdgeCA, specifying the TPP URL, Zone and Access token. EdgeCA will then get an issuing certificate and policy information from the TPP server. 

```
./edgeca server --url "..." --zone "..." --token "..." 
```

#### Pass-through mode

Instead of having EdgeCA bootstrap itself with an issuing certificate and then issue its own certificates using that issuing certificate, you can have it 
simply pass all certificate signing requests on to Venafi. To do that, use the `--passthrough` argument:

```
./edgeca server --url "..." --zone "..." --token "..."  --passthrough
```




## Use the EdgeCA CLI

Once the server is up and running, you can use the edgeca CLI to issue commands.
```
edgeca -h
EdgeCA is an ephemeral certificate authority

Usage:
  edgeca [command]

Available Commands:
  gencert     Create a Certificate
  gencsr      Create a CSR
  help        Help about any command

Flags:
  -h, --help   help for edgeca

Use "edgeca [command] --help" for more information about a command.
```

It supports two commands
- **gencsr** generates a CSR (Certificate Signing Request) used 
- **gencert** returns a signed certificate 

### Generate CSR  
```
gencsr -h
Create a CSR

Usage:
  edgeca gencsr [flags]

Flags:
      --cn string             Common Name (required)
  -c, --country string        Country
      --csr string            Output file for CSR
  -h, --help                  help for gencsr
      --key string            Output file for private key used to sign CSR
  -l, --locality string       Locality
  -o, --organization string   Organization
      --ou string             Organizational Unit
      --port int              TLS port of gRPC server (default 50025)
  -r, --refresh               Refresh the list of default values from the current policy
  -s, --server string         EdgeCA gRPC server name 
      --st string             State/Province
  -d, --tls-certs string      Location of certs for gRPC authentication 
```
To create a simple CSR file, do:

```
edgeca gencsr --cn localhost --organization ACME --csr test.csr --key test.key
```

If you are running edgecad in TPP mode, then it might be using policies with default values for CSRs. running edgeca with the **-r** argument will cause it to connect to edgecad, using gRPC and edgecad then use TPP to refresh information about the policy.

If for instance, the TPP policy specifies a default Organization of ABC, then the CSR generation will output:

``` 
edgeca gencsr --cn localhost --csr test.csr --key test.key -r
2021/01/19 17:03:30 Connecting to edgeca server to refresh policy information
2021/01/19 17:03:30 Loading TLS certificates from /home/me/.edgeca/certs
2021/01/19 17:03:30 Updated configuration file /home/me/.edgeca/configuration.yaml
2021/01/19 17:03:31 Generated CSR for [ CN=localhost,O=ABC ]
``` 

The default values are written into a configuration file so if we generate another CSR, without requesting the refresh step, then the default organization value is used but no connection is made to the gRPC server or TPP server:
```
edgeca gencsr --cn localhost --csr test.csr --key test.key
2021/01/19 17:05:55 Generated CSR for [ CN=localhost,O=ABC ]
```

### Sign certificate  
gencert is used to sign a CSR and return a signed certificate. If any values in the CSR don't match required values in the OPA policy, then it is rejected and the certificate not signed.

Generate a Certificate. Optional filenames can be specified for the certificate and private key
```
edgeca gencert -i test.csr -o test.cert -k test.key
```

A policy setting may reject the CSR
```
2020/11/26 22:32:45 could not get: rpc error: code = Unknown desc = Policy rejected CSR
```

otherwise the certificate and key are output

```
edgeca gencert -i test.csr -o test.cert -k test.key
2021/01/19 17:09:47 Connecting to edgeca server to sign certificate
2021/01/19 17:09:47 Loading TLS certificates from /home/me/.edgeca/certs
2021/01/19 17:09:47 Wrote Certificate to test.cert
2021/01/19 17:09:47 Wrote key to test.key
```


### Using GraphQL

EdgeCA includes basic support for GraphQL, using a built-in GraphQL server to provide machine identities via GraphQL. To use, start EdgeCA server with the `--graphql` argument, specifying the port to use

```
edgeca server --graphql 8888
```

This will start up EdgeCA listening for GraphQL requests on port 8888. EdgeCA also starts up a built-in playground for exploring the GraphQL API. 

To use, go to [http://localhost:8888/](http://localhost:8888/)

You can then enter a createCertificate mutation to create a certificate:

```
mutation {
  createCertificate(input: {commonName: "localhost",organization:"ACME inc"}){
    certificate,
    key,
    expiry
  }
}
```

The commonName argument is required, but optional arguments are `organization`, `organizationalUnit`, `locality`, `province` and  `country` 

To use the EdgeCA GraphQL server as a remote schema with Hashura, 

1. Start up EdgeCA as above
2. Install [Hasura](https://hasura.io/) locally using Docker Compose
4. Go to "Remote Schema"
5. Click "Add"
5. Create a new remote schema with the following values. Then click "Add Remote Schema" to confirm 
  - Remote Schema name: edgeca
  - GraphQL server URL: http://`your-ip-address`:8888/query   

6. In the GraphiQL query windows enter the mutation as above and run.