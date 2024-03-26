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
mock_directory: "/Users/esteves/Mindera/PROXY"
rules:
#example
- interceptor:
    url_regexp: ".*waitrose.*/api/favourites2-.*/v\n/favourites"
    header_key: "allow"
    method: "POST"

  actions:
    request:
      delay: 5
      add_query_parameter:
        - key: "<key>"
          value: "<value>"
      change_query_parameter:
        - key: "<key>"
          value: "<value>"
      replace_url_component:
        - key: "<key>"
          value: "<value>" 
      replace_body_component:
        - key: "<key>"
          value: "<value>" 
      replace_body: "{}"
      add_header:
        - key: "<key>"
          value: "<value>"
      save:
        - "header"
        - "cookie"
    response:
      file: "favourites/favourites.json"
      file_sequence: ["FileA", "FileB", "FileC"]
      add_header:
        - key: "<key>"
          value: "<value>"
      remove_header: "<key>"
      change_header_key:
        - key: "<key>"
          new_key: "<value>"
      body: "{}"
      delay: 5
      status_code: 200
      replace:
        replace: "regex"
        replacement: "string"
      save:
        - "header"
        - "cookie"
  marker: "https://api.github.com/emojis"
  active: false
```
