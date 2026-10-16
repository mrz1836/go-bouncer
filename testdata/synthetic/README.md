# Synthetic fixtures

Every file here was written by hand for go-bouncer's tests, to the shape the
Bouncer API v1.1 reference documents. None is a provider response or a copy of
a provider example: the addresses use the reserved `example.com`, `example.net`
and `example.org` domains, and every other value is invented.

`fixtures_test.go` fails when a fixture holds an address at any other domain.
