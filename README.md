Ref: https://github.com/m42e/certbot-dns-ispconfig/tree/master

Additional-Info: https://eff-certbot.readthedocs.io/en/stable/contributing.html#authenticators, https://certbot-dns-dnsimple.readthedocs.io/en/stable/#credentials

Adapted to use AllInkl as backend. -> https://kas.all-inkl.com/schnittstelle/dokumentation/phpdoc/index.html

## Usage (Example)

`certbot certonly --preferred-challenges dns-01 -d "*.yourdomain.com" -d yourdomain.com --authenticator dns-allinkl -v --dns-allinkl-credentials credentials.ini --dns-allinkl-propagation-seconds 600`

_credentials.ini_

```ini
dns_allinkl_username = wXXXXXXX
dns_allinkl_password = your_password
```