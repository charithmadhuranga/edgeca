# EdgeCA
**EdgeCA** is an ephemeral, in-memory CA providing service mesh machine identities.

This early release is meant for evaluation only.

To install the snap simply do

```
snap install edgeca
```

 
**edgeca** is the command line interface (CLI) application you will use to create CSRs and certificates

The client can generate CSR requests independently but to sign certificates it needs to have an instance of EdgeCA running in server mode as well either locally or remotely. 


The snap package starts up an instance of the edgeca server as a background process by default and the server does therefore not need to be manually launched. It starts up in the default self-signed mode. To run it in a different mode, set the config using `sudo` and restart the server:


```

$ sudo edgeca config graphql -p 8888
$ sudo snap restart edgeca.edgeca-server
```
 

To view the server logs do

```
snap logs -f edgeca.edgeca-server
```

The edgeca client connects to the server in a secure way using gRPC over TLS. To be able to connect to the remote server you need to copy the gRPC TLS certificate generated by the remote server, as per the log when running the server:

```
Writing TLS Client certificate to /var/snap/edgeca/current/edgeca-client-cert.pem
Writing TLS Client key to /var/snap/edgeca/current/edgeca-client-key.pem
```
Install the snap on the other system, and then copy the client certificate and key to your local `/var/snap/edgeca/current/` directory, where the client will find them.
