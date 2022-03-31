# Depooling a site
When editing this file, please also update
https://wikitech.wikimedia.org/wiki/DNS#Change_GeoDNS

To depool any site:

* Edit the `admin_state` file to include something like
`geoip/generic-map/eqiad => DOWN` (see examples within), commit, and run
`authdns-update` from any of the DNS servers.

# Other use of this repo

See https://wikitech.wikimedia.org/wiki/DNS -- the directions above are
only reproduced here for emergency use.
