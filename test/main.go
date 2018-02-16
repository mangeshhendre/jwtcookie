package main

//go:generate go-bindata-assetfs SPIGlass/...

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/mangeshhendre/jwtclient"

	ghandlers "github.com/gorilla/handlers"
	"github.com/justinas/alice"
	"github.com/rs/cors"

	"google.golang.org/grpc/grpclog"

	"github.com/mangeshhendre/jwtcookie"

	"github.com/gorilla/mux"
)

func main() {
	var (
		cn            = flag.String("cookie_name", "Bearer", "The name of the cookie element which contains the JWT")
		bd            = flag.String("base_directory", "SPIGlass", "The base directory of content to serve up")
		keyPath       = flag.String("key_path", "server.key", "The key to use for SSL encryptio")
		certPath      = flag.String("cert_path", "server.crt", "The cert to use for SSL encryptio")
		jwtCertPath   = flag.String("jwt_cert_path", "jwt_certs", "The path in which to locate JWT certificates, files should be named ISSUER.pem where ISSUER is the issuer expected.")
		serverAddress = flag.String("address", "0.0.0.0", "The address to listen on")
		serverPort    = flag.String("port", "8443", "The port to listen on")
		debug         = flag.Bool("debug", false, "Should we debug?")
	)
	flag.Parse()

	if *debug {
		log.Println("Debug mode enabled")
	}

	keyFunc, err := jwtclient.KeyFuncFromCertDir(*jwtCertPath)
	if err != nil {
		log.Fatalf("Unable to create key function: %v", err)
	}

	// First we need a router.
	router := mux.NewRouter()

	// Now we need middleware
	JWTC, err := jwtcookie.New(
		jwtcookie.CookieName(*cn),
		jwtcookie.KeyFunc(keyFunc),
	)
	if err != nil {
		grpclog.Fatalf("Unable to create jwt cookie middleware: %v", err)
	}

	openChain := alice.New(timeoutHandler, recoveryHandler, loggingHandler, JWTC.JWTRedirect)

	if *debug {
		router.PathPrefix("/").Handler(openChain.Then(http.FileServer(http.Dir(*bd)))).Methods("GET")
	} else {
		router.PathPrefix("/").Handler(openChain.Then(http.FileServer(assetFS()))).Methods("GET")
	}

	log.Fatal(http.ListenAndServeTLS(net.JoinHostPort(*serverAddress, *serverPort), *certPath, *keyPath, router))

}

func timeoutHandler(h http.Handler) http.Handler {
	return http.TimeoutHandler(h, 10*time.Second, "timed out")
}

func recoveryHandler(h http.Handler) http.Handler {
	return ghandlers.RecoveryHandler()(h)
}

func corshandler(h http.Handler) http.Handler {
	return cors.Default().Handler(h)
}

func loggingHandler(h http.Handler) http.Handler {
	return ghandlers.LoggingHandler(os.Stdout, h)
}
