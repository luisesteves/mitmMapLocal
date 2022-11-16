import re
import json
from mitmproxy import ctx, http
import yaml
import os
import logging
from time import sleep
import random 
from datetime import datetime
import os
import emoji

class MockResponse:
    def __init__(self):
        self.signal = "start"
        self.response_sequence_index = 0
        
        self.configuration_file = "cfg.yaml"
        self.cfg_modified_timestamp = os.path.getmtime(self.configuration_file)
        self.loaded = False
    
    def read_configuration(self):
        try:
            with open(self.configuration_file) as f:
                self.mock_configuration = yaml.safe_load(f)
        except IOError:    
            self.mock_configuration = "{file could not be found}"
        
    def response(self, flow):
        logging.info("🟢 Flow: %s" % flow.request.url)
        current_timestamp = datetime.timestamp(datetime.now())

        fileTs = os.path.getmtime(self.configuration_file)
        if self.cfg_modified_timestamp < fileTs or not self.loaded:
            logging.warning(">>> Reload")
            self.cfg_modified_timestamp = fileTs
            self.read_configuration()
            self.loaded = True

        def read_file(filename):
            data = ""
            try:
                absPath = os.path.abspath("%s/%s" % (self.mock_configuration["mock_directory"], filename))
                data = open(absPath).read()
            except IOError:
                try:
                    absPath = os.path.abspath(filename)
                    data = open(absPath).read()
                except IOError:
                    data = "{file could not be found}"
                return data
            return data

        if not self.mock_configuration["enable"]:
            logging.info("❌ mLoc disable")
            return

        intercepted = False
        #intercept the request with the all the interception rules
        for rule in self.mock_configuration["rules"]:
            interceptor = rule["interceptor"]
            actions = rule["actions"]
            marker = rule["marker"] if "marker" in rule else "heavy_exclamation_mark"
            if not rule["active"]:
                continue
    
            def log_filter(filter):
                logging.info("\U00002757 intercepted \"%s\" " % (filter))

            for filter, filter_value in interceptor.items():
                if filter == "url_regexp":
                    if re.search(filter_value, flow.request.url):
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "header_key":
                    if filter_value in flow.response.headers:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "method":
                    if filter_value == flow.request.method:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == "signal":
                    if filter_value == self.signal:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
            

            response_from_file_header = "__f_r_o_m__f_i_le__"
            # if the request was intercepeted then, lets run the actions
            if intercepted:
                flow.marked = ":%s:" % marker
                logging.info("\U00002757  %s", str(actions))

                if "response_file" in actions:
                    file = actions["response_file"]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                if "response_body" in actions:
                    flow.response.content = str.encode(actions["response_body"])
                if "status_code" in actions:
                    flow.response.status_code = actions["status_code"]
                if "add_header_request" in actions:
                    for header in actions["add_header_request"]:
                        flow.request.headers[header["key"]] = header["value"]
                if "response_file_sequence" in actions:
                    file = actions["response_file_sequence"][self.response_sequence_index]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                    if self.response_sequence_index == len(actions["response_file_sequence"]) - 1:
                        self.response_sequence_index = 0
                    else:
                        self.response_sequence_index += 1
                if "response_file_random" in actions:
                    randomIndex = random.randint(0, len(actions["response_file_random"]) - 1)
                    file = actions["response_file_random"][randomIndex]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                if "signal" in actions:
                    self.signal = actions["signal"]
                if "delay" in actions:
                    sleep(actions["delay"])
                if "save" in actions:
                    actions = actions["save"]
                    if "request" in actions:
                        with open('save.txt', 'a') as file:
                            for fild in actions["request"]:
                                file.write(flow.request.headers[fild] + "\n")
                            file.write("\n")

            intercepted = False

addons = [MockResponse()]
