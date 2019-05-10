; vim: set expandtab:smarttab
@           1D  IN SOA  ns0.wikimedia.org.  hostmaster.wikimedia.org.   (
                    {{ serial }}
                    12H     ; refresh
                    2H      ; retry
                    2W      ; expiry
                    1H      ; negative cache TTL
                    )

; Name servers

            1D  IN NS   ns0.wikimedia.org.
            1D  IN NS   ns1.wikimedia.org.
            1D  IN NS   ns2.wikimedia.org.

; Mail exchangers

            1H  IN MX   10  mx1001.wikimedia.org.
            1H  IN MX   50  mx2001.wikimedia.org.

; SPF records
@           600 IN TXT  "v=spf1 include:wikimedia.org ~all"

; CAA records
@           600 IN CAA 0 issue "letsencrypt.org"
@           600 IN CAA 0 iodef "mailto:dns-admin@wikimedia.org"

; Canonical names
            600 IN DYNA geoip!text-addrs

; Servers (alphabetic order)

; Service aliases

; Wikis (alphabetic order)

www         1D IN CNAME dyna.wikimedia.org.

; All languages will automatically be included here
{% include "helpers/langlist.tmpl" %}
