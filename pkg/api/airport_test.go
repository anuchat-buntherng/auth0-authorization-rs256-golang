package api_test

import (
	"golang-couchbase/pkg/api"
	"reflect"
	"testing"
)

type mockAirportRepo struct{}

func (m mockAirportRepo) SearchAirport(searchKey string) (api.SearchAirportResponse, error) {
	if searchKey == "" {
		return api.SearchAirportResponse{}, api.ErrorAirportSearchCriteriaRequired
	}

	if searchKey == "SFO" {
		var respData api.SearchAirportResponse
		respData.Status = api.StatusSuccess
		tests := []api.Airport{
			{AirportName: "San Francisco Intl"},
		}
		respData.Data = tests
		respData.Context = api.Context{"N1QL query - scoped to inventory: SELECT airportname FROM `travel-sample`.`inventory`.`airport` WHERE faa=$1"}

		return respData, nil
	}

	var respData api.SearchAirportResponse
	respData.Status = api.StatusSuccess
	respData.Context = api.Context{"N1QL query - scoped to inventory: SELECT airportname FROM `travel-sample`.`inventory`.`airport` WHERE faa=$1"}

	return respData, nil
}

func TestSearchAirportWithEmptySearchCriteria(t *testing.T) {
	mockRepo := mockAirportRepo{}
	mockAirportService := api.NewAirportService(&mockRepo)

	respData, err := mockAirportService.Search("")

	if respData.Status != "" || err == nil {
		t.Fatalf(`Search("") = %q, %v, want "", error`, respData.Status, err)
	}
}

func TestSearchAirport(t *testing.T) {
	mockRepo := mockAirportRepo{}
	mockAirportService := api.NewAirportService(&mockRepo)

	respData, err := mockAirportService.Search("SFO")

	if respData.Status == "" || err != nil {
		t.Fatalf(`Search("SFO") = %q, %v, want "", error`, respData.Status, err)
	}

	tests := []api.Airport{
		{AirportName: "San Francisco Intl"},
	}

	respEqual := reflect.DeepEqual(tests, respData.Data)

	if !respEqual {
		t.Fatal("Data dest is not equal to src")
	}
}
