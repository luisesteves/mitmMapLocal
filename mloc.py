import re
import json
from mitmproxy import ctx, http

mLocCfg = {
    "url regexp" : "<full path>trolley.json"
}

def readFile(fileLoc):
    data = ""
    try:
        data = open(fileLoc).read()
    except IOError:
        data = "{file could not be found}"

    return data

def response(flow):
    ctx.log.info("change response")
    for urlRegexp in mLocCfg:
        if re.search(urlRegexp, flow.request.url):
            flow.response.content = str.encode(readFile(mLocCfg[urlRegexp]))