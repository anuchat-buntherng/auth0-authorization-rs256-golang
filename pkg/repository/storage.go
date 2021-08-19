package repository

import (
	"fmt"
	"golang-couchbase/pkg/api"
	"log"
	"strings"

	"github.com/couchbase/gocb/v2"
)

type Storage interface {
	SearchAirport(searchKey string) (api.SearchAirportResponse, error)
}

type storage struct {
	cluster *gocb.Cluster
	bucket  *gocb.Bucket
}

func NewStorage(cluster *gocb.Cluster, bucket *gocb.Bucket) Storage {
	return &storage{cluster: cluster, bucket: bucket}
}

func (s *storage) SearchAirport(searchKey string) (api.SearchAirportResponse, error) {
	queryParams := make([]interface{}, 1)

	queryStr := "SELECT airportname FROM `travel-sample`.`inventory`.`airport`"
	if len(searchKey) == 3 {
		// FAA code
		queryParams[0] = strings.ToUpper(searchKey)
		queryStr = fmt.Sprintf("%s WHERE faa=$1", queryStr)
	} else if len(searchKey) == 4 && (strings.ToUpper(searchKey) == searchKey || strings.ToLower(searchKey) == searchKey) {
		// ICAO code
		queryParams[0] = strings.ToUpper(searchKey)
		queryStr = fmt.Sprintf("%s WHERE icao=$1", queryStr)
	} else {
		// Airport name
		queryParams[0] = "%" + strings.ToLower(searchKey) + "%"
		queryStr = fmt.Sprintf("%s WHERE LOWER(airportname) LIKE $1", queryStr)
	}

	var respData api.SearchAirportResponse
	respData.Context = append(respData.Context, fmt.Sprintf("N1QL query - scoped to inventory: %s", queryStr))
	rows, err := s.cluster.Query(queryStr, &gocb.QueryOptions{PositionalParameters: queryParams})
	if err != nil {
		log.Printf("Failed to execute airport search query: %s", err)
		return api.SearchAirportResponse{}, err
	}

	respData.Data = []api.Airport{}
	for rows.Next() {
		var airport api.Airport
		if err = rows.Row(&airport); err != nil {
			log.Printf("Error occurred during airport search result parsing: %s", err)
			return api.SearchAirportResponse{}, err
		}

		respData.Data = append(respData.Data, airport)
	}

	// We should always check for any errors that may have occurred on the stream.
	if err = rows.Err(); err != nil {
		log.Printf("Error occurred during airport search result streaming: %s", err)
		return api.SearchAirportResponse{}, err
	}

	respData.Status = api.StatusSuccess

	return respData, nil
}
