package main

import (
	"database/sql"
	"flag"
	"fmt"
	"golang-couchbase/pkg/api"
	"golang-couchbase/pkg/app"
	"golang-couchbase/pkg/repository"
	"os"

	"github.com/couchbase/gocb/v2"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var (
	defaultCBHost     = "54.179.164.44"
	defaultCBScheme   = "couchbase://" // Set to couchbase:// if using Couchbase Server Community Edition
	bucketName        = "travel-sample"
	defaultCBUsername = "Administrator"
	defaultCBPassword = "password"
	jwtSecret         = []byte("IAMSOSECRETIVE!")
)

func main() {
	os.Setenv("AUTH0_AUDIENCE", "account")
	os.Setenv("AUTH0_DOMAIN", "13.212.202.206:18080/auth/realms/pass-grant-realm")

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "this is the startup error: %s\n", err)
		os.Exit(1)
	}
}

// func run will be responsible for setting up db connections, routers etc
func run() error {
	connStr := envFlagString("CB_HOST", "host", defaultCBHost,
		"The connection string to use for connecting to the server")
	username := envFlagString("CB_USER", "user", defaultCBUsername,
		"The username to use for authentication against the server")
	password := envFlagString("CB_PASS", "password", defaultCBPassword,
		"The password to use for authentication against the server")
	scheme := envFlagString("CB_SCHEME", "scheme", defaultCBScheme,
		"The scheme to use for connecting to couchbase. Default to couchbases - set to couchbase:// when using couchbase community edition")
	flag.Parse()

	// Uncomment to enable the Go SDK logging.
	// gocb.SetLogger(&gocbLogWrapper{
	// 	logger: logrusLogger,
	// })

	// Connect the SDK to Couchbase Server.
	clusterOpts := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			Username: *username,
			Password: *password,
		},
	}
	cluster, err := gocb.Connect(*scheme+*connStr, clusterOpts)
	if err != nil {
		panic(err)
	}

	// Create a bucket instance, which we'll need for access to scopes and collections.
	bucket := cluster.Bucket(bucketName)

	// create storage dependency
	storage := repository.NewStorage(cluster, bucket)

	// err = storage.RunMigrations(connectionString)

	// if err != nil {
	// 	return err
	// }

	// create router dependency
	router := gin.Default()
	router.Use(cors.Default())

	// create airport service
	airportService := api.NewAirportService(storage)

	server := app.NewServer(router, airportService)

	// start the server
	err = server.Run()

	if err != nil {
		return err
	}

	return nil
}

func envFlagString(envName, name, value, usage string) *string {
	envValue := os.Getenv(envName)
	if envValue != "" {
		value = envValue
	}
	return flag.String(name, value, usage)
}

func setupDatabase(connString string) (*sql.DB, error) {
	// change "postgres" for whatever supported database you want to use
	db, err := sql.Open("postgres", connString)

	if err != nil {
		return nil, err
	}

	// ping the DB to ensure that it is connected
	err = db.Ping()

	if err != nil {
		return nil, err
	}

	return db, nil
}
