docker stop envoy-remote
docker stop envoy-local
docker stop http-echo

echo "Copying gRPC client certificates to a shared custom config volume"
cp ~/.edgeca/certs/edgeca-client-cert.pem ./custom-config/clientcert.pem
cp ~/.edgeca/certs/edgeca-client-key.pem ./custom-config/clientkey.pem
chmod -R a+rw ./custom-config

echo "create custom docker network"
docker network rm envoy-edgeca-poc-net
docker network create --driver bridge envoy-edgeca-poc-net

docker pull envoyproxy/envoy-dev:0e26d7fb01d1ebfe481e5fccd91d3e2e87030b9f

echo "start up remote envoy"
sudo docker run --rm -dit --name envoy-remote --network envoy-edgeca-poc-net \
      -v $(pwd)/custom-config:/custom-config\
      -p 9901:9901 \
      -p 10000:10000 \
      envoyproxy/envoy-dev:0e26d7fb01d1ebfe481e5fccd91d3e2e87030b9f \
        -c /custom-config/envoy-remote.yaml

sudo docker run --rm -dit --name envoy-local --network envoy-edgeca-poc-net \
      -v $(pwd)/custom-config:/custom-config\
      -p 20000:20000 \
      envoyproxy/envoy-dev:0e26d7fb01d1ebfe481e5fccd91d3e2e87030b9f \
        -c /custom-config/envoy-local.yaml


sudo docker run --rm -dit --name http-echo --network envoy-edgeca-poc-net \
      mendhak/http-https-echo:18


echo "connect remote envoy to network"
docker network connect bridge envoy-remote

echo "local and remote envoy started."

# To test, use 
# - curl http://localhost:20000 
# - openssl s_client --connect localhost:10000D
