# Envoy Secret Discovery Service (SDS) support

EdgeCA has POC support for [Envoy SDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret). 

This is currently under development and can be enabled by running with the "--sds" flag.


## Example 02: mTLS connection between two Envoy instances

In this example we have two instances of Envoy running on two different computers (which could be in two different physical locations).

Scenario:

1) User uses curl or browser to connect to http://localhost:20000

2) `envoy-local` is listening for http requests on port 20000. It uses mTLS authentication to forward them to port 10000 on `envoy-remote`.

3) `envoy-remote` forwards the request using http to an echo service running in a different docker container, on port 8080

so the flow is

 http ->  envoy-local:20000 ->  mTLS -> envoy-remote:10000 -> http-echo:8080


envoy-local is provided with a client certificate and envoy-remote with a server certificate for the mTLS authentication.

The example is set up on one host with two docker containers which share an user-defined network. To run use the `example02` directory contents:

```
cd example02
```
Update the two envoy configuration files, changing the IP address in 

```
address: 192.168.1.209
```
to your own IP address. This is the address used to connect to edgeca


1. Start EdgeCA with SDS mode enabled

```
./run-edgeca.sh
```

2. In a separate terminal start the two envoy instances using docker:

```
run-envoy-docker.sh
```


3. Test the connection

```
curl http://localhost:20000
```

The expected output is the webpage at https://edgeca.org, which is fetched by the remote envoy instance and sent to the local envoy over the mTLS connection, where it is available using `http` on port 20000.


You can also connect to the remote envoy to see the certificate info for the mTLS connection:

```
openssl s_client --connect localhost:10000
```

4. To view the envoy logs you can use


 ```
 docker logs envoy-local
 docker logs envoy-remote
 ```



## Example 01: Simple single-node setup

To run this example, do the following

```
cd example01
```

1. Start EdgeCA with SDS mode enabled

```
./run-edgeca.sh
```

2. In a separate window, start up Envoy

You first need to have [installed Envoy](https://www.envoyproxy.io/docs/envoy/latest/start/install)

If you have installed it using docker, then run

```
./run-envoy-docker.sh
```


This will start up Envoy with a the configuration from `custom-config/edgeca-envoy.yaml`. This configuration
- creates a listener on port 10000
- gets the TLS certificate for the listener using SDS from EdgeCA. To connect to EdgeCA it uses gRPC and the gRPC TLS client certificates to authenticate against EdgeCA
- sets up a proxy redirecting to https://edgeca.org



3. To test this, use curl

```
curl --cacert ~/.edgeca/certs/CA.pem https://localhost:10000
```

This curl command will use the CA cert from EdgeCA. It will connect to Envoy, which will in turn use TLS certificates provided to it by EdgeCA.

The expected output is an JSON file with information about your http request
