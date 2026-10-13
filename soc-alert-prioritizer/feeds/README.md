# Threat feeds

Every file in this directory is loaded by the local feed provider at start-up.

* `*.txt` - one indicator per line (IP, CIDR, domain, URL or hash). Lines
  starting with `#` are comments. The file name becomes the tag on a match,
  so `tor_exit_nodes.txt` tags hits with `tor-exit-nodes`.
* `*.csv` - header `indicator,type,score,tags,description`; tags are
  separated by `;` and `score` is 0-100.

`sample_feed.csv` matches the infrastructure used by the synthetic data
generator (documentation IP ranges and `.test` domains). Replace or extend it
with exports from your own TIP, MISP feeds, abuse.ch lists, etc.
