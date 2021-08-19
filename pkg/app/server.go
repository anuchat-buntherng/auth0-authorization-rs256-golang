package app

import (
	"golang-couchbase/pkg/api"
	"log"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router         *gin.Engine
	airportService api.AirportService
}

func NewServer(router *gin.Engine, airportService api.AirportService) *Server {
	return &Server{
		router:         router,
		airportService: airportService,
	}
}

func (s *Server) Run() error {
	// run function that initializes the routes
	r := s.Routes()

	// run the server through the router
	err := r.Run()

	if err != nil {
		log.Printf("Server - there was an error calling Run on router: %v", err)
		return err
	}

	return nil
}
