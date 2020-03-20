# Depooling a site
When editing this file, please also update
https://wikitech.wikimedia.org/wiki/DNS#Change_GeoDNS

To depool any site _except_ esams:

* Edit the `admin_state` file to include something like
`geoip/generic-map/eqiad => DOWN` (see examples within), commit, and run
`authdns-update` from any of the DNS servers.

To depool esams:

* Edit the `config` file switching the `$include` directive from
`geo-maps` to `geo-maps-esams-offline` (one should be commented out,
and the other uncommented), commit, and run `authdns-update` from any
of the DNS servers.

# Other use of this repo

See https://wikitech.wikimedia.org/wiki/DNS -- the directions above are
only reproduced here for emergency use.
