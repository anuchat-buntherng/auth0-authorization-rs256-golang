package api

import (
	"errors"
	"time"
)

type User struct {
	ID            int       `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Name          string    `json:"name"`
	Age           int       `json:"age"`
	Height        int       `json:"height"`
	Sex           string    `json:"sex"`
	ActivityLevel int       `json:"activity_level"`
	WeightGoal    string    `json:"weight_goal"`
	Email         string    `json:"email"`
}

type NewUserRequest struct {
	Name          string `json:"name"`
	Age           int    `json:"age"`
	Height        int    `json:"height"`
	Sex           string `json:"sex"`
	ActivityLevel int    `json:"activity_level"`
	WeightGoal    string `json:"weight_goal"`
	Email         string `json:"email"`
}

type UpdateActivityLevelRequest struct {
	Email         string `json:"email"`
	ActivityLevel int    `json:"activity_level"`
}

type Weight struct {
	Weight             int `json:"weight"`
	UserID             int `json:"user_id"`
	BMR                int `json:"bmr"`
	DailyCaloricIntake int `json:"daily_caloric_intake"`
}

type NewWeightRequest struct {
	Weight int `json:"weight"`
	UserID int `json:"user_id"`
}

//

var (
	StatusSuccess = "success"
	StatusFailure = "failure"
)

var (
	ErrorAirportSearchCriteriaRequired = errors.New("airport search criteria required")
)

var (
	ErrorUserExists        = errors.New("user already exists")
	ErrorUserNotFound      = errors.New("user does not exist")
	ErrorUsernameNotMatch  = errors.New("username does not match token")
	ErrorBadPassword       = errors.New("password does not match")
	ErrorBadAuthHeader     = errors.New("bad authentication header format")
	ErrorBadAuth           = errors.New("invalid auth token")
	ErrorInsufficientScope = errors.New("insufficient scope")
	ErrorInvalidAudience   = errors.New("invalid audience")
	ErrorInvalidIssuer     = errors.New("invalid issuer")
)

type Airport struct {
	AirportName string `json:"airportname"`
}

type Hotel struct {
	Country     string `json:"country"`
	City        string `json:"city"`
	State       string `json:"state"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
}

// jsonContext should not be confused with context.Context.
type Context []string

type SearchAirportResponse struct {
	Status  string    `json:"status"`
	Data    []Airport `json:"data"`
	Context Context   `json:"context"`
}
