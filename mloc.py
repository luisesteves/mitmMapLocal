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

    def reload_configuration(self):
        fileTs = os.path.getmtime(self.configuration_file)
        if self.cfg_modified_timestamp < fileTs or not self.loaded:
            logging.warning(">>> Reload")
            self.cfg_modified_timestamp = fileTs
            self.read_configuration()
            self.loaded = True

    def interceptor(self, flow):
        #intercept the request with the all the interception rules
        for rule in self.mock_configuration["rules"]:
            #logging.info("✍️ rule: %s" % str(rule))
            interceptor = rule["interceptor"]
            actions = rule["actions"]
            marker = rule["marker"] if "marker" in rule else "heavy_exclamation_mark"
            
            if not rule["active"]:
                continue

            def log_filter(filter):
                logging.info("🔴 intercepted \"%s\" " % (filter))

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
            if intercepted:
                # we dont need to continue to try other rules
                flow.marked = ":%s:" % marker
                break

        return {"intercepted": intercepted, "actions": actions}

    def request(self, flow):
        logging.info("🔼  Flow: %s" % flow.request.url)
        self.reload_configuration()

        intercepted = self.interceptor(flow)

        # if the request was intercepeted then, lets run the actions
        if intercepted["intercepted"]:
            request_actions = intercepted["actions"]["request"]
            if request_actions is not None:
                logging.info("🪛  %s", str(request_actions))
                if "add_query_parameter" in request_actions:
                    for query_parameter in request_actions["add_query_parameter"]:
                        flow.request.query[query_parameter["key"]] = query_parameter["value"]
                if "add_header_request" in request_actions:
                    for header in request_actions["add_header_request"]:
                        flow.request.headers[header["key"]] = header["value"]
                if "save" in request_actions:
                    save_actions = request_actions["save"]
                    with open('save.txt', 'a') as file:
                        for fild in save_actions:
                            file.write(flow.request.headers[fild] + "\n")
                        file.write("\n")
        
    def response(self, flow):

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
        
        logging.info("⬇️  Flow: %s" % flow.request.url)
        self.reload_configuration()

        if not self.mock_configuration["enable"]:
            logging.info("❌ mLoc disable")
            return

        intercepted = self.interceptor(flow)

        # if the request was intercepeted then, lets run the actions
        if intercepted["intercepted"]:
            response_actions = intercepted["actions"]["response"]
            if response_actions is not None:
                logging.info("🪛  %s", str(response_actions))

                response_from_file_header = "__f_r_o_m__f_i_le__"
                if "file" in response_actions:
                    file = response_actions["file"]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                if "body" in response_actions:
                    #logging.info("🪛  body")
                    flow.response.content = str.encode(response_actions["body"])
                if "status_code" in response_actions:
                    flow.response.status_code = response_actions["status_code"]
                if "file_sequence" in response_actions:
                    file = response_actions["file_sequence"][self.response_sequence_index]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                    if self.response_sequence_index == len(response_actions["file_sequence"]) - 1:
                        self.response_sequence_index = 0
                    else:
                        self.response_sequence_index += 1
                if "file_random" in response_actions:
                    randomIndex = random.randint(0, len(response_actions["file_random"]) - 1)
                    file = response_actions["file_random"][randomIndex]
                    flow.request.headers[response_from_file_header] = file
                    flow.response.headers[response_from_file_header] = file
                    flow.response.content = str.encode(read_file(file))
                if "signal" in response_actions:
                    self.signal = response_actions["signal"]
                if "delay" in response_actions:
                    sleep(response_actions["delay"])
                if "save" in response_actions:
                    save_actions = response_actions["save"]
                    with open('save.txt', 'a') as file:
                        for fild in save_actions:
                            file.write(flow.request.headers[fild] + "\n")
                        file.write("\n")

addons = [MockResponse()]
