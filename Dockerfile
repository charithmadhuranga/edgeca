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

FROM golang:1.16-alpine AS build_base

RUN apk add --no-cache git

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

COPY --from=build_base /tmp/edgeca/bin/edgeca /app/edgeca

EXPOSE 50025

ENTRYPOINT ["/app/edgeca"]