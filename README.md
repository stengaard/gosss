Source:
    https://github.com/stengaard/gosss
    
[![Build Status](https://travis-ci.org/stengaard/gosss.svg?branch=master)](https://travis-ci.org/stengaard/gosss)


Stengaard's Secret Server
-------------------------
A simple way of distributing secrets in a closed network environment.

A blatant friend ripoff of Steve's Secret Server
(http://github.com/skx/sss). Re-written in Go.


How Does it Work?
-----------------
`gosss` runs a TLS protected webserver port `1337`. A client wanting
to fetch credentials for a service (say `db`) can now connect to
https://gosss.example.com:1337/db - gosss will then look into
`secrets/<client ID>/db.json` and return the content found there.

Directory layout:

    |-- README.md
    |-- main.go
    `-- secrets
        `-- 127.0.0.1
            `-- db.json

Note that if no TLS key is given `gosss` will bind to 127.0.0.1 and
thus only be available for testing.


Todo
----
    - Add AWS EC2 lookup
