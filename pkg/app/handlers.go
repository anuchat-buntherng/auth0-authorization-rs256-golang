package app

import (
	"golang-couchbase/pkg/api"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
	ResourceAccess ResourceAccess `json:"resource_access"`
}

type ResourceAccess struct {
	UIAuthen RoleGroup `json:"ui-authen"`
	Account  RoleGroup `json:"account"`
}
type RoleGroup struct {
	Roles []string `json:"roles"`
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		// Verify 'aud' claim
		aud := os.Getenv("AUTH0_AUDIENCE")
		log.Printf("aud: %s", aud)
		checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
		if !checkAud {
			return token, api.ErrorInvalidAudience
		}
		// Verify 'iss' claim
		iss := "http://" + os.Getenv("AUTH0_DOMAIN")
		log.Printf("iss: %s", iss)
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, api.ErrorInvalidIssuer
		}

		cert, err := getPemCert(token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	},
	SigningMethod: jwt.SigningMethodRS256,
})

func (s *Server) ApiStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		writeJsonSuccess(c, "weight tracker API running smoothly", nil, nil)
	}
}

func writeJsonResponse(c *gin.Context, code int, response interface{}) {
	c.Header("Content-Type", "application/json")

	c.JSON(code, response)
}

func writeResponseSuccess(c *gin.Context, response interface{}) {
	writeJsonResponse(c, http.StatusOK, response)
}

func writeResponseFailure(c *gin.Context, response interface{}) {
	writeJsonResponse(c, http.StatusInternalServerError, response)
}

func writeJsonResponseWithContext(c *gin.Context, code int, status string, data interface{}, context api.Context) {
	c.Header("Content-Type", "application/json")

	response := map[string]interface{}{
		"status":  status,
		"data":    data,
		"context": context,
	}

	c.JSON(code, response)
}

func writeJsonSuccess(c *gin.Context, status string, data interface{}, context api.Context) {
	writeJsonResponseWithContext(c, http.StatusOK, status, data, context)
}

func writeJsonFailure(c *gin.Context, status string, data interface{}, context api.Context) {
	writeJsonResponseWithContext(c, http.StatusInternalServerError, status, data, context)
}

func checkScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	claims, ok := token.Claims.(*CustomClaims)

	log.Printf("ok: %s", strconv.FormatBool(ok))
	log.Printf("token.Scope: %s", claims.Scope)
	// log.Printf("token.Raw: %s", token.Raw)
	log.Printf("token.Signature: %s", token.Signature)
	log.Printf("token.Valid: %s", strconv.FormatBool(token.Valid))

	log.Printf("token.ResourceAccess.UIAuthen.Roles: %s", strings.Join(claims.ResourceAccess.UIAuthen.Roles, ", "))
	log.Printf("token.ResourceAccess.Account.Roles: %s", strings.Join(claims.ResourceAccess.Account.Roles, ", "))

	hasScope := false
	// if ok && token.Valid {
	if ok {
		result := strings.Split(claims.Scope, " ")
		for i := range result {
			if result[i] == scope {
				hasScope = true
			}
		}
	}

	log.Printf("hasScope: %s", strconv.FormatBool(hasScope))

	return hasScope
}

func getPemCert(token *jwt.Token) (string, error) {
	// cert := "-----BEGIN CERTIFICATE-----\n" + "MIICrzCCAZcCBgF7KofU3jANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBwYXNzLWdyYW50LXJlYWxtMB4XDTIxMDgwOTEwNDczMFoXDTMxMDgwOTEwNDkxMFowGzEZMBcGA1UEAwwQcGFzcy1ncmFudC1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJVSi4kFUukEb7riwknCgAkJbWS5fbCNl081YhI3lJv+At6Gb01MQ3laUDv+biLtnIHeJtUImIuR6sudCOEunP+aSTm8s+goH7IVeSU2fUzXjY8er3bT8H6XMSoRUpiXl68uil1FYDdxrcp+TsuIhycNpjOC6CrqxEZhB/gvUuor2qpJ3wt6bSlgQjciAmKTxrNVRCIdE2q3MxhATGt7r8p7EJfxmhsfoC9aOYxCPoWDdb6TGrB+HawwDjtQ1+BT7dx+e5hBYEbzVedeN7P3d2J5sJLrFwxE0jD/M/IZot65Rfy4ZHLvPn3idNAxRrrwd1h+9GK0xy3DCkOPMaVhMekCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGw0s5fmBRIxIO/0Y8d4nbvj2xLDSWOftVyvZWxI1MRLyQ6cmeTmd9qrwbpARbJZh5jXe5EJQZD9Tr2Ro+GEgnfxpfsvp6ae1NZhyFQqzjlHyk0BXe5E190OdFa0jGfr3/zmkQ1LG6DPX8tx+5q0bKhL0iZHToijtFcBG6NY3JMmwNuLapcKSCo3Kox1FCjbsnpN+NVmNY3JfXSLdCg4VU4zrU3873SSIEnrJ3fxbf5owV+Xejp23W0Hp1OrkbnHTZ9NQEsSo8WHCCUjES51oG2J7QsaO9CzHmIg6mq+yl0QZnHQmoVT2/xQssgil2m3nvb68OHqxTgFiqZOWviKMBw==" + "\n-----END CERTIFICATE-----"
	cert := "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlVKLiQVS6QRvuuLCScKACQltZLl9sI2XTzViEjeUm/4C3oZvTUxDeVpQO/5uIu2cgd4m1QiYi5Hqy50I4S6c/5pJObyz6CgfshV5JTZ9TNeNjx6vdtPwfpcxKhFSmJeXry6KXUVgN3Gtyn5Oy4iHJw2mM4LoKurERmEH+C9S6ivaqknfC3ptKWBCNyICYpPGs1VEIh0TarczGEBMa3uvynsQl/GaGx+gL1o5jEI+hYN1vpMasH4drDAOO1DX4FPt3H57mEFgRvNV5143s/d3YnmwkusXDETSMP8z8hmi3rlF/Lhkcu8+feJ00DFGuvB3WH70YrTHLcMKQ48xpWEx6QIDAQAB" + "\n-----END PUBLIC KEY-----"
	return cert, nil
	// cert := ""
	// resp, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")

	// if err != nil {
	// 	return cert, err
	// }
	// defer resp.Body.Close()

	// var jwks = Jwks{}
	// err = json.NewDecoder(resp.Body).Decode(&jwks)

	// if err != nil {
	// 	return cert, err
	// }

	// for k, _ := range jwks.Keys {
	// 	if token.Header["kid"] == jwks.Keys[k].Kid {
	// 		cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
	// 	}
	// }

	// if cert == "" {
	// 	err := errors.New("Unable to find appropriate key.")
	// 	return cert, err
	// }

	// return cert, nil
}

// func responseJSON(message string, w http.ResponseWriter, statusCode int) {
// 	response := Response{message}

// 	jsonResponse, err := json.Marshal(response)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(statusCode)
// 	w.Write(jsonResponse)
// }

func (s *Server) CheckJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtMid := *jwtMiddleware
		if err := jwtMid.CheckJWT(c.Writer, c.Request); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func (s *Server) ManageStoreAuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeaderParts := strings.Split(c.Request.Header.Get("Authorization"), " ")
		token := authHeaderParts[1]
		log.Printf("token: %s", token)

		hasScope := checkScope("manage-store", token)

		if !hasScope {
			log.Printf("handler error: %s", api.ErrorInsufficientScope)
			writeJsonFailure(c, api.ErrorInsufficientScope.Error(), nil, nil)
			c.AbortWithStatus(http.StatusForbidden)
		}
	}
}

func (s *Server) SearchAirport() gin.HandlerFunc {
	return func(c *gin.Context) {
		searchKey := c.Query("search")

		if searchKey == "" {
			log.Printf("handler error: %s", api.ErrorAirportSearchCriteriaRequired)
			writeJsonFailure(c, api.ErrorAirportSearchCriteriaRequired.Error(), nil, nil)
			return
		}

		respData, err := s.airportService.Search(searchKey)

		if err != nil {
			log.Printf("handler error: %s", err)
			writeJsonFailure(c, err.Error(), nil, nil)
			return
		}

		writeResponseSuccess(c, respData)
	}
}
