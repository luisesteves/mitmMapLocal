import re
import json
from mitmproxy import ctx, http
import yaml
import os
import logging

reload = 12

class MockResponse:
    def __init__(self):
        logging.warning(">>> Reload")
        self.signal = "start"
        def readConfiguration():
            try:
                with open('cfg.yaml') as f:
                    data = yaml.safe_load(f)
            except IOError:    
                data = "{file could not be found}"
                
            return data
        self.mockCfg = readConfiguration()
    
    def response(self, flow):
        #https://docs.mitmproxy.org/stable/api/mitmproxy/http.html#Request
        logging.info(">>> Signal: " + self.signal)
        def readFile(filename):
            data = ""
            try:
                absPath = os.path.abspath("../PROXY/" + filename)
                logging.info("modify reponse from file: " + absPath)
                data = open(absPath).read()
            except IOError:
                data = "{file could not be found}"
            return data

        if not self.mockCfg["enable"]:
            logging.info("mock enable")
            return

        intercepted = False
        #intercept the request with the all the interception rules
        for rule in self.mockCfg["rules"]:
            interceptor = rule["interceptor"]
            actions = rule["actions"]
    
            if not rule["active"]:
                continue
    
            for filter, filterValue in interceptor.items():
                if filter == "urlRegexp":
                    if re.search(filterValue, flow.request.url):
                        logging.info(filterValue + " -> " + flow.request.url)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "headerKey":
                    if filterValue in flow.response.headers:
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "method":
                    if filterValue == flow.request.method:
                        logging.info(">>> filter by method")
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "signal":
                    if filterValue == self.signal:
                        logging.info(">>> filter by Signal")
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
    

            # if the request was intercepeted then, lets run the actions
            if intercepted:
                logging.info("change response")
                file = actions["responseFromFile"]
                flow.request.headers["from_file"] = file
                if "responseFromFile" in actions:
                    flow.response.content = str.encode(readFile(file))
                if "statusCode" in actions:
                    logging.info("modify reponse code")
                    flow.response.status_code = actions["statusCode"]
                if "addHeader" in actions:
                    for header in actions["addHeader"]:
                        logging.info("add header")
                        flow.response.headers[header["key"]] = header["value"]
                if "responseFromFiles" in actions:
                    logging.info(actions["responseFromFiles"][0])
                if "signal" in actions:
                    logging.info(">>> signal: " + actions["signal"])
                    self.signal = actions["signal"]

            intercepted = False

addons = [MockResponse()]
