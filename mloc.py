import re
import json
from collections.abc import Sequence
from mitmproxy import ctx, http, command, flow
import yaml
import os
import logging
from time import sleep
import asyncio
import random 
from datetime import datetime
from mitmproxy.utils import emoji
from typing import Optional

@command.command("all.markers")
def all_markers():
    "Create a new flow showing all marker values"
    for marker in emoji.emoji:
        ctx.master.commands.call(
            "view.flows.create", "get", f"https://example.com/{marker}"
        )
        # Check if the flow was successfully created and added to the view
        if ctx.master.view:
            ctx.master.commands.call("flow.mark", [ctx.master.view[-1]], marker)
        else:
            ctx.log.warn(f"No flow available to mark for marker: {marker}")


class MockResponse:

    # Constants for configuration and interception rules
    KEY_URL_REGEXP = "url_regexp"
    KEY_BODY_REGEXP = "body_regexp"
    KEY_HEADER_KEY = "header_key"
    KEY_METHOD = "method"
    KEY_SIGNAL = "signal"
    KEY_INTERCEPTOR = "interceptor"
    KEY_ACTIONS = "actions"
    KEY_MARKER = "marker"
    KEY_ACTIVE = "active"
    KEY_RULE_SWITCH = "rule_switch"

    # Constants for intercepted actions
    KEY_INTERCEPTED = "intercepted"
    KEY_ACTIONS = "actions"
    KEY_REQUEST = "request"
    KEY_RESPONSE = "response"

    # Constants for intercepted and response actions
    KEY_INTERCEPTED = "intercepted"
    KEY_ACTIONS = "actions"
    KEY_RESPONSE = "response"

    # Constants for response actions keys
    KEY_FILE = "file"
    KEY_BODY = "body"
    KEY_REPLACE = "replace"
    KEY_REPLACEMENT = "replacement"
    KEY_STATUS_CODE = "status_code"
    KEY_ADD_HEADER = "add_header"
    KEY_REMOVE_HEADER = "remove_header"
    KEY_CHANGE_HEADER_KEY = "change_header_key"
    KEY_NEW_KEY = "new_key"
    KEY_FILE_SEQUENCE = "file_sequence"
    KEY_FILE_RANDOM = "file_random"
    KEY_SIGNAL = "signal"
    KEY_DELAY = "delay"
    KEY_SAVE = "save"
    KEY_SEARCH = "search"

    KEY_ADD_QUERY_PARAMETER = "add_query_parameter"
    KEY_REMOVE_QUERY_PARAMETER = "remove_query_parameter"
    KEY_CHANGE_QUERY_PARAMETER = "change_query_parameter"
    KEY_REPLACE_URL_COMPONENT = "replace_url_component"
    KEY_REPLACE_BODY_COMPONENT = "replace_body_component"
    KEY_REPLACE_BODY = "replace_body"
    KEY_ADD_HEADER_REQUEST = "add_header_request"
    HOST = "host"
    PATH = "path"
    KILL = "kill"

    
    # @command.command("mock.switch")
    # def switch(self, flow: flow.Flow):
    #     self.rule_switch = flow.request.url

    #     for rule in self.mock_configuration["rules"]:
    #         interceptor = rule["interceptor"]

    #         for filter, filter_value in interceptor.items():
    #             if filter == "url_regexp" and re.search(filter_value, flow.request.url):
    #                 if rule["active"]:
    #                     rule["rule_switch"] = not rule.get("rule_switch", True)
    #                     logging.warning("🎚️ switch : %s - %s" % (filter_value, rule["rule_switch"]))


    # disable or enable flow mock
    @command.command("m.flowOnOff")
    def switch_map_flow(self):
        flow_url = ctx.master.view.focus.flow.request.url
        if self.hard_disable_switch.get(flow_url):
            self.hard_disable_switch.update({flow_url: False})

            ctx.master.view.focus.flow.marked = ""
            logging.warning(f"🔀 hard disable On - {flow_url}")
        else:
            self.hard_disable_switch.update({flow_url: True})
            logging.warning(f"🔀 Setting hard disable to Off - {flow_url}")

    @command.command("m.flowOn")
    def switch_map_flow_on(self):
        flow_url = ctx.master.view.focus.flow.request.url
        self.hard_disable_switch.update({flow_url: False})
        logging.warning(f"🔀 Setting hard enable - {flow_url}")

    @command.command("m.flowOff")
    def switch_map_flow_off(self):
        flow_url = ctx.master.view.focus.flow.request.url
        self.hard_disable_switch.update({flow_url: True})
        logging.warning(f"🔀 Setting hard disable - {flow_url}")

    # disable or enable kill all
    @command.command("m.killAll")
    def mock_killAll(self):
        self.mock_toggle_kill_all = not self.mock_toggle_kill_all
        logging.warning(f"kill all toggle: {self.mock_toggle_kill_all}")


    @command.command("m.mockTest")
    def mock_test(self, flows: Sequence[flow.Flow]):
        for f in flows:
            # logging.warning(f"FLOW : {f}")
            f.marked = ":grapes:"

    @command.command("m.timestamp")
    def mock_time(self):
        ts = ctx.master.view.focus.flow.timestamp_start
        readable = datetime.fromtimestamp(ts).strftime('%M:%S.%f')[:-3]
        logging.warning(f"Request started at {readable}")
        ctx.master.view.focus.flow.request.path += f" | {readable}"

    @command.command("m.kill")
    def mock_kill(self):
        flow_url = ctx.master.view.focus.flow.request.url
        if self.mock_toggle_kill.get(flow_url):
            self.mock_toggle_kill.update({flow_url: False})
            logging.warning(f"{self.mock_toggle_kill}")

            ctx.master.view.focus.flow.marked = ""
            logging.warning(f"❌ kill off - {flow_url}")
        else:
            self.mock_toggle_kill.update({flow_url: True})
            logging.warning(f"❌ Setting kill on - {flow_url}")

    @command.command("m.error")
    # def mock_error(self, flow: flow.Flow, error: int):
    def mock_error(self, error: int = 500):
        logging.warning("❌  mock error")
        # self.hard_error_switch.update({flow.request.url: error})
        ctx.master.view.focus.flow.marked = ":eight_spoked_asterisk:"
        self.hard_error_switch.update({ctx.master.view.focus.flow.request.url: error})
        logging.warning(self.hard_error_switch)
        if error == 0:
            self.hard_error_switch = {}
            logging.warning("clear")

    @command.command("m.delay")
    def mock_delay(self, delay: int = 1):
        logging.warning("🥱 mock delay")
        self.hard_delay.update({ctx.master.view.focus.flow.request.url: delay})
        logging.warning(self.hard_delay)
        if delay == 0:
            self.hard_delay = {}
            logging.warning("clear")

    @command.command("m.find")
    def mock_find(self, term: str):
        logging.warning(f"⏺️  search: {term}")
        self.mock_search = term

    @command.command("m.onoff")
    def mock_onoff(self):
        self.mock_toggle_state = not self.mock_toggle_state
        logging.warning(f"⏺️  mock toggle: {self.mock_toggle_state}")

    @command.command("m.on")
    def mock_on(self):
        self.mock_toggle_state = True
        logging.warning(f"⏺️  mock toggle: {self.mock_toggle_state}")

    @command.command("m.off")
    def mock_off(self):
        self.mock_toggle_state = False
        logging.warning(f"⏺️  mock toggle: {self.mock_toggle_state}")

    @command.command("m.flow")
    def mock_flow(self):
        self.signal = "start"
        logging.warning("🌼 flow restart")

    @command.command("m.zzz")
    def mock_zzz(self, delay: int = 1):
        self.bad_network_delay = delay
        logging.warning(f"🥱 bad network: {delay}")

    def __init__(self):
        self.signal = "start"
        self.bad_network_delay = 0
        self.response_sequence_index = 0

        self.configuration_file = "cfg.yaml"
        self.cfg_modified_timestamp = os.path.getmtime(self.configuration_file)
        self.loaded = False
        self.mock_toggle_state = False
        self.mock_toggle_kill_all = False
        self.mock_toggle_kill = {}
        self.mock_search = ""
        self.rule_switch = ""
        self.response_from_file_header = "__f_r_o_m__f_i_le__"
        self.hard_error_switch = {}
        self.hard_delay = {}
        self.hard_disable_switch = {}
        self.fast_mock = {}
    
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
        if self.hard_disable_switch.get(flow.request.url):
            logging.warning(f" Appying hard disable: {flow.request.url}")
            flow.marked = ":grey_exclamation:"
            return {"intercepted": False, "actions": {}}
            # :arrows_counterclockwise: :bangbang: :grey_exclamation:

        if self.fast_mock.get(flow.request.url):
            logging.warning(f"Fast mock: {flow.request.url}")
            flow.marked = f":fast_forward:"
            return {
                self.KEY_INTERCEPTED: True,
                self.KEY_ACTIONS: {
                    self.KEY_RESPONSE: {
                        self.KEY_FILE: self.fast_mock.get(flow.request.url)
                    }
                }
            }

        # Intercept the request with all the interception rules
        for rule in self.mock_configuration["rules"]:
            # logging.info(f"✍️ rule: {rule}")
            interceptor = rule[self.KEY_INTERCEPTOR]
            actions = rule[self.KEY_ACTIONS]
            marker = rule.get(self.KEY_MARKER, "heavy_exclamation_mark")
            intercepted = False

            if not rule.get(self.KEY_ACTIVE, False):
                continue
            elif not rule.get(self.KEY_RULE_SWITCH, True):
                continue

            def log_filter(filter):
                logging.info(f"🔴 intercepted \"{filter}\"")

            for filter, filter_value in interceptor.items():
                if filter == self.KEY_URL_REGEXP:
                    if re.search(filter_value, flow.request.url):
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == self.KEY_BODY_REGEXP:
                    log_filter(flow.request.content.decode("utf-8"))
                    if re.search(filter_value, flow.request.content.decode("utf-8")):
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == self.KEY_HEADER_KEY:
                    if filter_value in flow.response.headers:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == self.KEY_METHOD:
                    if filter_value == flow.request.method:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break
                if filter == self.KEY_SIGNAL:
                    if filter_value == self.signal:
                        log_filter(filter)
                        intercepted = True
                        continue
                    else:
                        intercepted = False
                        break

            if intercepted:
                # we dont need to continue to try other rules
                flow.marked = f":{marker}:"
                # flow.request.url += "  #########"
                break

        return {"intercepted": intercepted, "actions": actions}

    async def request(self, flow):
    # def request(self, flow):
        logging.info(f"🔼  Flow: {flow.request.url}")
        self.reload_configuration()

        if self.mock_toggle_kill_all:
            logging.warning("❌ kill all")
            flow.kill()
            return

        if self.mock_toggle_kill.get(flow.request.url):
            logging.warning(f"❌ kill : {flow.request.url}")
            flow.kill()
            return

        if not self.mock_toggle_state:
            logging.info("❌ mLoc disable")
            flow.marked = ":arrow_heading_down:"
            return

        for key in self.hard_delay:
           if key == flow.request.url:
                logging.info("🕥✅ applying hard dealy")
                flow.marked = ":zzz:"
                # sleep(self.hard_delay[key])
                await asyncio.sleep(self.hard_delay[key])

        intercepted = self.interceptor(flow)

        # if the request was intercepted then, let's run the actions
        if (
            intercepted[self.KEY_INTERCEPTED]
            and intercepted[self.KEY_ACTIONS] is not None
            and self.KEY_REQUEST in intercepted[self.KEY_ACTIONS]
            and intercepted[self.KEY_ACTIONS][self.KEY_REQUEST] is not None
        ):

            request_actions = intercepted[self.KEY_ACTIONS][self.KEY_REQUEST]
            logging.info(f"🪛  {request_actions}")

            if self.KEY_DELAY in request_actions:
                logging.info("🕓")
                sleep(request_actions[self.KEY_DELAY])

            if self.KEY_ADD_QUERY_PARAMETER in request_actions:
                for query_parameter in request_actions[self.KEY_ADD_QUERY_PARAMETER]:
                    flow.request.query[query_parameter["key"]] = query_parameter["value"]
            
            if self.KEY_REMOVE_QUERY_PARAMETER in request_actions:
                for query_parameter in request_actions[self.KEY_REMOVE_QUERY_PARAMETER]:
                    query = flow.request.query.copy()
                    if query_parameter["key"] in query:
                        del query[query_parameter["key"]]
                    flow.request.query = query

            if self.KEY_CHANGE_QUERY_PARAMETER in request_actions:
                for query_parameter in request_actions[self.KEY_CHANGE_QUERY_PARAMETER]:
                    flow.request.query[query_parameter["key"]] = query_parameter["value"]

            if self.KEY_REPLACE_URL_COMPONENT in request_actions:
                for query_parameter in request_actions[self.KEY_REPLACE_URL_COMPONENT]:
                    flow.request.url = flow.request.url.replace(query_parameter["key"], query_parameter["value"])

            if self.KEY_REPLACE_BODY_COMPONENT in request_actions:
                for query_parameter in request_actions[self.KEY_REPLACE_BODY_COMPONENT]:
                    content = flow.request.text
                    logging.info(f">>>> key  {query_parameter['key']}")
                    logging.info(f">>>> {query_parameter['value']}")
                    flow.request.content = str.encode(re.sub(query_parameter["key"], query_parameter["value"], content))

            if self.KEY_REPLACE_BODY in request_actions:
                flow.request.content = str.encode(request_actions[self.KEY_REPLACE_BODY])

            if self.KEY_ADD_HEADER_REQUEST in request_actions:
                for header in request_actions[self.KEY_ADD_HEADER_REQUEST]:
                    flow.request.headers[header["key"]] = header["value"]

            if self.HOST in request_actions:
                flow.request.host = request_actions[self.HOST]
            if self.PATH in request_actions:
                flow.request.path = request_actions[self.PATH]

            if self.KILL in request_actions and request_actions[self.KILL]:
                logging.warning("❌ killed")
                flow.kill()
                return

            if self.KEY_SAVE in request_actions:
                save_actions = request_actions[self.KEY_SAVE]
                with open('save.txt', 'a') as file:
                    for field in save_actions:
                        file.write(flow.request.headers[field] + "\n")
                    file.write("\n")
        else:
            flow.marked = ""
            if self.response_from_file_header in flow.request.headers:
                flow.request.headers.pop(self.response_from_file_header)

    async def response(self, flow):

        logging.info(f"⬇️  Flow: {flow.request.url}")

        def read_file(filename):
            try:
                abs_path = os.path.abspath(f"{self.mock_configuration['mock_directory']}/{filename}")
                return open(abs_path).read()
            except IOError:
                try:
                    abs_path = os.path.abspath(filename)
                    return open(abs_path).read()
                except IOError:
                    data = f"{abs_path} could not be found"
                    logging.error(data)
                return data

        def search(flow, pattern, string):
            logging.info("🔍 searching")
            matches = re.finditer(self.mock_search, flow.response.text)
            for match in matches:
                logging.warning(f"🔍 found: '{match.group()}'")
                flow.marked = ":eye:"

        self.reload_configuration()

        if not self.mock_toggle_state:
            logging.info("❌ mLoc disable")
            return

        for key in self.hard_delay:
           if key == flow.request.url:
                logging.info("🕥✅ applying hard dealy")
                flow.marked = ":zzz:"
                # sleep(self.hard_delay[key])
                await asyncio.sleep(self.hard_delay[key])
           
        for key in self.hard_error_switch:
           if key == flow.request.url:
                logging.info("❌✅ applying error state")
                flow.marked = ":eight_spoked_asterisk:"
                flow.response.status_code = self.hard_error_switch[key]
                flow.response.content = str.encode("")
                return

        intercepted = self.interceptor(flow)

        # if the request was intercepeted then, lets run the actions
        # Check if the request was intercepted and run the actions
        if (
            intercepted[self.KEY_INTERCEPTED]
            and intercepted.get(self.KEY_ACTIONS)
            and self.KEY_RESPONSE in intercepted[self.KEY_ACTIONS]
            and intercepted[self.KEY_ACTIONS][self.KEY_RESPONSE] is not None
        ):
            response_actions = intercepted[self.KEY_ACTIONS][self.KEY_RESPONSE]
            logging.info(f"🪛  {response_actions}")

            if self.KEY_FILE in response_actions:
                file = response_actions[self.KEY_FILE]
                flow.request.headers[self.response_from_file_header] = file
                flow.response.headers[self.response_from_file_header] = file
                flow.response.content = str.encode(read_file(file))

            if self.KEY_BODY in response_actions:
                flow.response.content = str.encode(response_actions[self.KEY_BODY])

            if self.KEY_REPLACE in response_actions:
                replace = response_actions[self.KEY_REPLACE]
                replacement = response_actions[self.KEY_REPLACEMENT]
                content = flow.response.text
                flow.response.content = str.encode(re.sub(replace, replacement, content))

            if self.KEY_STATUS_CODE in response_actions:
                flow.response.status_code = response_actions[self.KEY_STATUS_CODE]

            if self.KEY_ADD_HEADER in response_actions:
                for header in response_actions[self.KEY_ADD_HEADER]:
                    flow.response.headers[header["key"]] = header["value"]

            if self.KEY_REMOVE_HEADER in response_actions:
                flow.response.headers.pop(response_actions[self.KEY_REMOVE_HEADER])

            if self.KEY_CHANGE_HEADER_KEY in response_actions:
                for header in response_actions[self.KEY_CHANGE_HEADER_KEY]:
                    value = flow.response.headers[header["key"]]
                    logging.info(f"👺  {value}")
                    flow.response.headers.pop(header["key"])
                    flow.response.headers[header[self.KEY_NEW_KEY]] = value

            if self.KEY_FILE_SEQUENCE in response_actions:
                file = response_actions[self.KEY_FILE_SEQUENCE][self.response_sequence_index]
                flow.request.headers[self.response_from_file_header] = file
                flow.response.headers[self.response_from_file_header] = file
                flow.response.content = str.encode(read_file(file))
                if self.response_sequence_index == len(response_actions[self.KEY_FILE_SEQUENCE]) - 1:
                    self.response_sequence_index = 0
                else:
                    self.response_sequence_index += 1

            if self.KEY_FILE_RANDOM in response_actions:
                randomIndex = random.randint(0, len(response_actions[self.KEY_FILE_RANDOM]) - 1)
                file = response_actions[self.KEY_FILE_RANDOM][randomIndex]
                flow.request.headers[self.response_from_file_header] = file
                flow.response.headers[self.response_from_file_header] = file
                flow.response.content = str.encode(read_file(file))
            
            if self.KEY_SIGNAL in response_actions:
                self.signal = response_actions[self.KEY_SIGNAL]
                logging.info(f"🚦 {self.signal}")

            if self.KEY_DELAY in response_actions:
                logging.info("🕓")
                sleep(response_actions[self.KEY_DELAY])

            if self.KILL in response_actions and response_actions[self.KILL]:
                logging.warning("❌ killed response")
                flow.kill()
                return

            if self.KEY_SAVE in response_actions:
                save_actions = response_actions[self.KEY_SAVE]
                with open('save.txt', 'a') as file:
                    for field in save_actions:
                        file.write(flow.request.headers[field] + "\n")
                    file.write("\n")

            if self.KEY_SEARCH in response_actions:
                search(flow, self.mock_search, flow.response.text)

        if self.mock_search != "":
            search(flow, self.mock_search, flow.response.text)

        if self.bad_network_delay != 0:
            flow.marked = ":zzz:"
            sleep(self.bad_network_delay)

addons = [MockResponse()]

