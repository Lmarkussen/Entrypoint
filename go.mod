module entrypoint

go 1.24.0

require github.com/hirochachacha/go-smb2 v1.1.0

require (
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
)

require (
	github.com/Azure/go-ntlmssp v0.1.0
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667
	github.com/microsoft/go-mssqldb v1.9.2
	golang.org/x/crypto v0.38.0
)

replace golang.org/x/crypto => ./third_party/golang.org/x/crypto

replace github.com/microsoft/go-mssqldb => ./third_party/github.com/microsoft/go-mssqldb

replace golang.org/x/sys => ./third_party/golang.org/x/sys
