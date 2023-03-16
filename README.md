# mitmMapLocal
This allows to reply a response locally

## dependencies
* Mitmproxy version: 2.0.2 or greater
* yaml package for python

pip install pyyaml

## how to start
create the following file:
`~/.mitmproxy/config.yaml` 
with the content:
```
scripts:
  - ~/<path to this repro>/mitmMapLocal/mloc.py
allow_hosts:
  - .*waitrose.*
validate_inbound_headers:
  false
```
start the proxy
`> mitmproxy`

## configuration examples

```yaml
enable: true
mock_directory: "<path to your mock folder>"
rules:
#example
- interceptor:
    url_regexp: ".*waitrose.*/api/favourites2-.*/v\n/favourites"
    signal: "start"
  actions:
    response_file: "<relative path>/favourites.json"
    response_file_sequence: ["file-a", "file-b", "file-c"]
    response_file_random: ["file-a", "file-b", "file-c"]
    response_body: "{}"
    signal: "stop"
    add_header_request:
      key: "key"
      value: "value"
    status_code: 200
    delay: 2
    add_header:
       - key: "<key>"
         value: "<value>"
    save:
      request:
        - "authorization"
        - "cookie"
  marker: "https://api.github.com/emojis"
  active: false
```