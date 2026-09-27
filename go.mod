// The substrate's shared Go modules. Today it holds one: trust.
//
// It lives inside the PortfoliDEX repository rather than in its own — see
// trust/doc.go, "Where this module lives", for why, and for what graduating
// it to github.com/NorthwesternAnalytics/substrate-go actually costs.
module github.com/NorthwesternAnalytics/substrate-go

go 1.25.0

require github.com/golang-jwt/jwt/v5 v5.2.2
