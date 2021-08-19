package api

// AirportService contains the methods of the user service
type AirportService interface {
	Search(searchKey string) (SearchAirportResponse, error)
}

// Airport repository is what lets our service do db operations without knowing anything about the implementation
type AirportRepository interface {
	SearchAirport(string) (SearchAirportResponse, error)
}

type airportService struct {
	storage AirportRepository
}

func NewAirportService(airportRepo AirportRepository) AirportService {
	return &airportService{storage: airportRepo}
}

func (u *airportService) Search(searchKey string) (SearchAirportResponse, error) {
	respData, err := u.storage.SearchAirport(searchKey)

	if err != nil {
		return SearchAirportResponse{}, err
	}

	return respData, nil
}
