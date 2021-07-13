# EdgeCA
**EdgeCA** is an ephemeral, in-memory CA providing service mesh machine identities, automating the management and issuance of TLS certificates.

It provides developers with a fast, easy, and integrated source of machine identities whilst also providing security teams with the required policy and oversight.  

It also enables ephemeral certificate-based authorization, which reduces the need for permanent access credentials, explicit access revocation or traditional SSH key management. 

It is easy to install and simple to use.

- `edgeca server` starts up EdgeCA as a server, which supports mTLS gRPC, GraphQL and Envoy SDS as different ways of providing machine identities.
- `edgeca gencsr` generates a CSR file
- `edgeca gencert` connects to the EdgeCA Server using mTLS gRPC to sign a CSR request and provide a certificate and private key.

EdgeCA can run in a number of modes. 
1. It can generate a self-signed Root CA certificate.
2. You can provide the Root CA certificate to use. 
3. EdgeCA can connect to the [Venafi vCert](https://github.com/Venafi/vcert) TPP backend to get an issuing certificate, which is then used to generate certificates locally. 
4. It is also possible to disable completely all local certificate signing and have EdgeCA pass all signing requests directly on to the Venafi back-end.

EdgeCA is a flexible open source solution, written in Go, and licenced with the Apache 2.0 Licence

For more information see the [EdgeCA Wiki pages](https://github.com/edgesec-org/edgeca/wiki). 

The easiest way to install the application is to use [snaps](./snap)

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-white.svg)](https://snapcraft.io/edgeca)

```
snap install edgeca
```

Alternatively, use Docker

```
docker pull edgesec/edgeca
```

or build EdgeCA from source:

```
git clone https://github.com/edgesec-org/edgeca.git
cd edgeca
make
```




[![Go Report Card](https://goreportcard.com/badge/github.com/edgesec-org/edgeca)](https://goreportcard.com/report/github.com/edgesec-org/edgeca)

## Contributing to EdgeCA
**EdgeCA** is an open source project currently in early development stages. We welcome and appreciate all contributions from the developer community.
Please read our documentation on [contributing](https://github.com/edgesec-org/edgeca/blob/main/CONTRIBUTING.md) for more information. To report a problem or share an idea, create an [Issue](https://github.com/edgesec-org/edgeca/issues) and then use [Pull Requests](https://github.com/edgesec-org/edgeca/pulls) to contribute bug fixes or proposed enhancements. Got questions? [Join us on Slack](https://join.slack.com/t/edgesec/signup)!

## License
Copyright 2020-2021 © [EdgeSec Ltd](https://edgesec.org). All rights reserved.

EdgeCA is licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/edgesec-org/edgeca/blob/main/LICENSE) for the full license text.
