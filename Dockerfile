# /*******************************************************************************
#  * Copyright 2021 EdgeSec Ltd
#  *
#  * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
#  * in compliance with the License. You may obtain a copy of the License at
#  *
#  * http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software distributed under the License
#  * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  * or implied. See the License for the specific language governing permissions and limitations under
#  * the License.
#  *
#  *******************************************************************************/


FROM alpine:3.14 as hsm_build

ARG SOFTHSMV2_VERSION=2.6.1
WORKDIR /tmp/hsm

RUN apk add --no-cache \
    autoconf \
    automake \
    build-base \
    libtool \
    openssl-dev \
  && wget -O SoftHSMv2.tar.gz \
    https://github.com/opendnssec/SoftHSMv2/archive/${SOFTHSMV2_VERSION}.tar.gz \
  && tar -xf SoftHSMv2.tar.gz \
  && cd SoftHSMv2-${SOFTHSMV2_VERSION} \
  && ./autogen.sh \
  && ./configure \
  && make \
  && make install
  

FROM golang:1.16-alpine AS edgeca_build

RUN apk add --no-cache git gcc g++
WORKDIR /tmp/edgeca
COPY go.mod .
COPY go.sum .
RUN go mod download
ARG version
COPY . .
RUN echo "-X github.com/edgesec-org/edgeca.Version=$version"
RUN go build -ldflags "-X github.com/edgesec-org/edgeca.Version=$version" -o bin/edgeca ./cmd/edgeca/

# Start fresh from a smaller image
FROM alpine:3.9 

RUN apk add --no-cache libstdc++ musl opensc openssl 

COPY --from=edgeca_build /tmp/edgeca/bin/edgeca /app/edgeca
COPY --from=hsm_build /usr/local/lib/softhsm /usr/local/lib/softhsm
COPY --from=hsm_build /usr/local/bin/* /usr/local/bin/

EXPOSE 50025

ENTRYPOINT ["/app/edgeca"]
