import re
import json
from mitmproxy import ctx, http
import yaml
import os

reload = 12

class MockResponse:
    def __init__(self):
        def readConfiguration():
            try:
                with open('cfg.yaml') as f:
                    data = yaml.load(f)
            except IOError:    
                data = "{file could not be found}"
                ctx.log.info("error while open the yaml file")
            return data
        self.mockCfg = readConfiguration()
    
    def response(self, flow):
        def readFile(filename):
            data = ""
            try:
                absPath = os.path.abspath("./mockdata/" + filename)
                ctx.log.info("modify reponse from file: " + absPath)
                data = open(absPath).read()
            except IOError:
                data = "{file could not be found}"
            return data

        if not self.mockCfg["enable"]:
            ctx.log.info("mock enable")
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
                        ctx.log.info(filterValue + " -> " + flow.request.url)
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
    

            # if the request was intercepeted then, lets run the actions
            if intercepted:
                ctx.log.info("change response")
                flow.request.headers["intercepted"] = "true"
                if "responseFromFile" in actions:
                    flow.response.content = str.encode(readFile(actions["responseFromFile"]))
                if "statusCode" in actions:
                    ctx.log.info("modify reponse code")
                    flow.response.status_code = actions["statusCode"]
    
            intercepted = False

def start():
    return MockResponse()