/*******************************************************************************
 * Copyright 2021 EdgeSec Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 *******************************************************************************/

package server

import (
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/edgesec-org/edgeca/internal/auth/jwt"
	"github.com/edgesec-org/edgeca/internal/server/graphqlimpl/graph"
	"github.com/edgesec-org/edgeca/internal/server/graphqlimpl/graph/generated"
	"github.com/go-chi/chi"
)

func initJWTToken() {
	token, _ := jwt.GenerateToken()
	log.Infof("Use the following HTTP header for GraphQL JWT authentication:\n{\"Authorization\": \"%s\"}", token)

}

//StartGraphqlServer starts up the graphql server
func StartGraphqlServer(port int) {

	initJWTToken()

	sPort := strconv.Itoa(port)

	router := chi.NewRouter()
	router.Use(jwt.Middleware())

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &graph.Resolver{}}))

	router.Handle("/", playground.Handler("GraphQL playground", "/query"))
	router.Handle("/query", srv)

	log.Debugf("connect to http://localhost:%s/ for GraphQL playground", sPort)
	log.Fatal(http.ListenAndServe(":"+sPort, router))
}
