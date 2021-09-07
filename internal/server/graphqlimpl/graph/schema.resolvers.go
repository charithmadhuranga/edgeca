package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"crypto/x509/pkix"
	"fmt"

	"github.com/edgesec-org/edgeca/internal/auth/jwt"
	"github.com/edgesec-org/edgeca/internal/issuer"
	"github.com/edgesec-org/edgeca/internal/server/graphqlimpl/graph/generated"
	"github.com/edgesec-org/edgeca/internal/server/graphqlimpl/graph/model"
	"github.com/edgesec-org/edgeca/internal/state"
	"github.com/prometheus/common/log"
)

func (r *mutationResolver) CreateCertificate(ctx context.Context, input model.NewCertificate) (*model.Certificate, error) {

	var err error
	var pemCertificate, pemPrivateKey, expiryStr string
	var subject pkix.Name

	userID := jwt.UserIDFromContext(ctx)
	if userID == "" {
		var result model.Certificate
		return &result, fmt.Errorf("access denied - JWT token missing/invalid")
	}
	subject.CommonName = input.CommonName

	if input.Organization != nil {
		subject.Organization = []string{*input.Organization}
	}

	if input.OrganizationalUnit != nil {
		subject.OrganizationalUnit = []string{*input.OrganizationalUnit}
	}

	if input.Locality != nil {
		subject.Locality = []string{*input.Locality}
	}

	if input.Province != nil {
		subject.Province = []string{*input.Province}
	}

	if input.Country != nil {
		subject.Country = []string{*input.Country}
	}

	log.Debugln("GraphQL request: certificate for " + subject.CommonName + " from issuer: " + state.GetStateDescription())

	if state.UsingPassthrough() {
		_, pemCertificate, pemPrivateKey, err = state.GenerateCertificateUsingTPP(subject)
		if err == nil {
			expiryStr, err = issuer.GetExpiryOfPEMCertificate([]byte(pemCertificate))
		}
	} else {

		var bCertificate, bPrivateKey []byte

		bCertificate, bPrivateKey, expiryStr, err = issuer.GenerateCertificateUsingX509Subject(subject)
		pemCertificate = string(bCertificate)
		pemPrivateKey = string(bPrivateKey)
	}

	var result model.Certificate
	var subCACert = string(state.GetSubCAPEMCert())
	result.Certificate = pemCertificate + subCACert
	result.Expiry = expiryStr
	result.Key = pemPrivateKey
	return &result, err
}

func (r *queryResolver) Certificate(ctx context.Context) ([]*model.Certificate, error) {
	panic(fmt.Errorf("not implemented"))
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
