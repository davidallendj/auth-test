package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi"
	"github.com/go-chi/jwtauth/v5"
	"github.com/gorilla/handlers"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

func loadPublicKeyFromURL(url string) (*jwtauth.JWTAuth, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK: %v", err)
	}
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			continue
		}

		return jwtauth.New(jwa.RS256.String(), nil, rawkey), nil
	}

	return nil, fmt.Errorf("failed to create token auth")
}

func main() {
	router := chi.NewRouter()
	tokenAuth, err := loadPublicKeyFromURL("http://127.0.0.1:4444/.well-known/jwks.json")
	if err != nil {
		fmt.Printf("failed to load public key from URL: %v\n", err)
		return
	}
	router.Group(func(r chi.Router) {
		r.Use(
			jwtauth.Verifier(tokenAuth),
			jwtauth.Authenticator(tokenAuth),
		)

		// router.NotFoundHandler = s.Logger(http.NotFoundHandler(), "NotFoundHandler")
		var handler http.Handler
		handler = handlers.CombinedLoggingHandler(os.Stdout, handler)
		r.Get("/test", func(w http.ResponseWriter, r *http.Request) { fmt.Printf("hello world!") })
	})

	http.ListenAndServe(":27770", router)
}
