import re
import json
from mitmproxy import ctx, http, command
import yaml
import os
import logging
from time import sleep
import random 
from datetime import datetime
import os
import emoji

class MockResponse:
    
    @command.command("mock.toggle")
    def mock_toggle(self):
        self.mock_toggle_state = not self.mock_toggle_state
        logging.warning("⏺️  mock toggle: %s" % self.mock_toggle_state)

    @command.command("mock.flow")
    def mock_flow(self):
        self.signal = "start"
        logging.warning("🌼 flow restart")
    
    @command.command("mock.zzz")
    def mock_zzz(self):
        self.bad_network = not self.bad_network
        logging.warning("🥱 bad network %s" % self.bad_network)

    def __init__(self):
        self.signal = "start"
        self.bad_network = False
        self.response_sequence_index = 0
        
        self.configuration_file = "cfg.yaml"
        self.cfg_modified_timestamp = os.path.getmtime(self.configuration_file)
        self.loaded = False
        self.mock_toggle_state = False
    
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
            self.mock_toggle_state = self.mock_configuration["enable"]

    def interceptor(self, flow):
        #intercept the request with the all the interception rules
        for rule in self.mock_configuration["rules"]:
            #logging.info("✍️ rule: %s" % str(rule))
            interceptor = rule["interceptor"]
            actions = rule["actions"]
            marker = rule["marker"] if "marker" in rule else "heavy_exclamation_mark"
            intercepted = False
            
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
                if filter == "body_regexp":
                    if re.search(filter_value, flow.request.content.decode("utf-8")):
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

        if not self.mock_toggle_state:
            logging.info("❌ mLoc disable")
            flow.marked = ":arrow_heading_down:"
            return
        
        intercepted = self.interceptor(flow)

        # if the request was intercepeted then, lets run the actions
        if intercepted["intercepted"] and "request" in intercepted["actions"] and intercepted["actions"]["request"] is not None:

            request_actions = intercepted["actions"]["request"]
            logging.info("🪛  %s", str(request_actions))
            if "delay" in request_actions:
                logging.info("🕓")
                sleep(request_actions["delay"])
            if "add_query_parameter" in request_actions:
                for query_parameter in request_actions["add_query_parameter"]:
                    flow.request.query[query_parameter["key"]] = query_parameter["value"]
            if "change_query_parameter" in request_actions:
                for query_parameter in request_actions["change_query_parameter"]:
                    flow.request.query[query_parameter["key"]] = query_parameter["value"]
            if "replace_url_component" in request_actions:
                for query_parameter in request_actions["replace_url_component"]:
                    flow.request.url = flow.request.url.replace(query_parameter["key"], query_parameter["value"])
            if "replace_body_component" in request_actions:
                for query_parameter in request_actions["replace_body_component"]:
                    content = flow.request.text
                    logging.info(">>>> key  %s", str(query_parameter["key"]))
                    logging.info(">>>> %s", str(query_parameter["value"]))
                    flow.request.content = str.encode(re.sub(query_parameter["key"], query_parameter["value"], content))
            if "replace_body" in request_actions:
                flow.request.content = str.encode(request_actions["replace_body"])
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

        # if not self.mock_configuration["enable"]:
        #     logging.info("❌ mLoc disable")
        #     return

        if not self.mock_toggle_state:
            logging.info("❌ mLoc disable")
            return

        intercepted = self.interceptor(flow)

        # if the request was intercepeted then, lets run the actions
        if intercepted["intercepted"] and "response" in intercepted["actions"] and intercepted["actions"]["response"] is not None:
            response_actions = intercepted["actions"]["response"]
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
            if "replace" in response_actions:
                replace_cfg = response_actions["replace"]
                replace = replace_cfg["replace"]
                replacement = replace_cfg["replacement"]
                content = flow.response.text
                flow.response.content = str.encode(re.sub(replace, replacement, content))
            if "status_code" in response_actions:
                flow.response.status_code = response_actions["status_code"]
            if "add_header" in response_actions:
                for header in response_actions["add_header"]:
                    flow.response.headers[header["key"]] = header["value"]
            if "remove_header" in response_actions:
                flow.response.headers.pop(response_actions["remove_header"])
            if "change_header_key" in response_actions:
                for header in response_actions["change_header_key"]:
                    value = flow.response.headers[header["key"]]
                    logging.info("👺  %s", str(value))
                    flow.response.headers.pop(header["key"])
                    flow.response.headers[header["new_key"]] = value
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
                logging.info("🚦 %s", self.signal)
            if "delay" in response_actions:
                logging.info("🕓")
                sleep(response_actions["delay"])
            if "save" in response_actions:
                save_actions = response_actions["save"]
                with open('save.txt', 'a') as file:
                    for fild in save_actions:
                        file.write(flow.request.headers[fild] + "\n")
                    file.write("\n")
        
        if self.bad_network:
            flow.marked = ":zzz:"
            sleep(1)

addons = [MockResponse()]
