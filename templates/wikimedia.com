; vim: set expandtab:smarttab
; {{ serial_comment }}
@ 600 IN SOA ns0.wikimedia.org. hostmaster.wikimedia.org. {{ serial_num }} 12H 2H 2W 600

; Name servers

@           1H  IN NS   ns0.wikimedia.org.
@           1H  IN NS   ns1.wikimedia.org.
@           1H  IN NS   ns2.wikimedia.org.


; SPF txt and rr records
; No email for parked domains (T193408)
@           600 IN TXT  "v=spf1 -all"

; CAA records
@           600 IN CAA 0 issue "letsencrypt.org"
@           600 IN CAA 0 issue "amazonaws.com"
@           600 IN CAA 0 iodef "mailto:dns-admin@wikimedia.org"

; Domain root (can't use CNAME here)
@           600 IN DYNA geoip!ncredir-addrs

; Wikimedia Enterprise
enterprise  600 IN CNAME d1ih19hol8udi5.cloudfront.net.

; Validation for cloudfront-issued TLS certificate for the above:
_6be3c80dc6418fd7e2c91d6c54a7f758.enterprise 600 IN CNAME _5d04049dae06818d7d7e7b83d4f68f11.nfyddsqlcy.acm-validations.aws.

; Wikis (alphabetic order), which are not covered by langlist.tmpl

arbcom-cs               1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-cs.m             1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-de               1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-de.m             1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-en               1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-en.m             1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-fi               1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-fi.m             1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-nl               1D IN CNAME ncredir-lb.wikimedia.org.
arbcom-nl.m             1D IN CNAME ncredir-lb.wikimedia.org.
commons                 1D IN CNAME ncredir-lb.wikimedia.org.
meta                    1D IN CNAME ncredir-lb.wikimedia.org.
nostalgia               1D IN CNAME ncredir-lb.wikimedia.org.
quote                   1D IN CNAME ncredir-lb.wikimedia.org.
quality                 1D IN CNAME ncredir-lb.wikimedia.org.
quality.m               1D IN CNAME ncredir-lb.wikimedia.org.
sep11                   1D IN CNAME ncredir-lb.wikimedia.org.
sources                 1D IN CNAME ncredir-lb.wikimedia.org.
species                 1D IN CNAME ncredir-lb.wikimedia.org.
ten                     1D IN CNAME ncredir-lb.wikimedia.org.
ten.m                   1D IN CNAME ncredir-lb.wikimedia.org.
test                    1D IN CNAME ncredir-lb.wikimedia.org.
test2                   1D IN CNAME ncredir-lb.wikimedia.org.
test.m                  1D IN CNAME ncredir-lb.wikimedia.org.
test2.m                 1D IN CNAME ncredir-lb.wikimedia.org.
textbook                1D IN CNAME ncredir-lb.wikimedia.org.
wg-en                   1D IN CNAME ncredir-lb.wikimedia.org.
www                     1D IN CNAME ncredir-lb.wikimedia.org.
zh-tw                   1D IN CNAME ncredir-lb.wikimedia.org.

; All languages will automatically be included here.
{% include "helpers/lang-ncredir.tmpl" %}

; Other websites

15              1D IN CNAME ncredir-lb.wikimedia.org.
bugzilla        1D IN CNAME ncredir-lb.wikimedia.org.
careers         1D IN CNAME ncredir-lb.wikimedia.org.
donate          1D IN CNAME ncredir-lb.wikimedia.org.
download        1D IN CNAME ncredir-lb.wikimedia.org.
jobs            1D IN CNAME ncredir-lb.wikimedia.org.
m               1D IN CNAME ncredir-lb.wikimedia.org.
mail            1D IN CNAME ncredir-lb.wikimedia.org.
shop            1D IN CNAME ncredir-lb.wikimedia.org.
stats           1D IN CNAME ncredir-lb.wikimedia.org.
store           1D IN CNAME ncredir-lb.wikimedia.org.
zero            1D IN CNAME ncredir-lb.wikimedia.org.
