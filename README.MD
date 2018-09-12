check-certs
===========

This is a simple utility written in Go to check SSL certificates for a list of hosts. Each certificate in the host's certificate chain is checked for the following:

 Expiration date. By default, you will be alerted if a certificate will expire within 30 days. This can be adjusted with `-years=X`, `-months=X`, and/or `-days=X`.


Usage looks something like:

```
./check-certs -hosts="./path/to/file/with/hosts"
