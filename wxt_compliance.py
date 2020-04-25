#!/bin/#!/usr/bin/env python3

import os
import sys
import uuid
import logging
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from urllib.parse import urlparse, quote

from webexteamssdk import WebexTeamsAPI, ApiError, AccessToken
webex_api = WebexTeamsAPI()

import ddb_single_table

import json, requests
from datetime import datetime, timedelta, timezone
import time
from flask import Flask, request, redirect, url_for

import concurrent.futures
import signal

flask_app = Flask(__name__)
flask_app.config["DEBUG"] = True
requests.packages.urllib3.disable_warnings()

logger = logging.getLogger()

WEBEX_SCOPE = ["spark-compliance:events_read", "spark-compliance:memberships_read",
    "spark-compliance:memberships_write", "spark-compliance:messages_read", "spark-compliance:messages_write",
    "spark-compliance:rooms_read", "spark-compliance:team_memberships_read", "spark-compliance:team_memberships_write",
    "spark-compliance:teams_read", "spark:people_read"] # "spark:rooms_read", "spark:kms"
STATE_CHECK = "webex is great" # integrity test phrase
EVENT_CHECK_INTERVAL = 15
SAFE_TOKEN_DELTA = 3600 # safety seconds before access token expires - renew if smaller

def sigterm_handler(_signo, _stack_frame):
    "When sysvinit sends the TERM signal, cleanup before exiting."

    flask_app.logger.info("Received signal {}, exiting...".format(_signo))
    
    thread_executor._threads.clear()
    concurrent.futures.thread._threads_queues.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

thread_executor = concurrent.futures.ThreadPoolExecutor()
username = None

class AccessTokenAbs(AccessToken):
    def __init__(self, access_token_json):
        super().__init__(access_token_json)
        if not "expires_at" in self._json_data.keys():
            self._json_data["expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.expires_in)).timestamp())
        flask_app.logger.debug("Access Token expires in: {}s, at: {}".format(self.expires_in, self.expires_at))
        if not "refresh_token_expires_at" in self._json_data.keys():
            self._json_data["refresh_token_expires_at"] = str((datetime.now(timezone.utc) + timedelta(seconds = self.refresh_token_expires_in)).timestamp())
        flask_app.logger.debug("Refresh Token expires in: {}s, at: {}".format(self.refresh_token_expires_in, self.refresh_token_expires_at))
        
    @property
    def expires_at(self):
        return self._json_data["expires_at"]
        
    @property
    def refresh_token_expires_at(self):
        return self._json_data["refresh_token_expires_at"]

def save_tokens(user_email, tokens):
    flask_app.logger.debug("AT timestamp: {}".format(tokens.expires_at))
    token_record = {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "refresh_token_expires_at": tokens.refresh_token_expires_at
    }
    ddb_single_table.save_db_record(user_email, "TOKENS", tokens.expires_at, **token_record)
    
def get_tokens_for_user(user_email):
    db_tokens = ddb_single_table.get_db_record(user_email, "TOKENS")
    
    if db_tokens:
        tokens = AccessTokenAbs(db_tokens)
        flask_app.logger.debug("Got tokens: {}".format(tokens))
        ## TODO: check if token is not expired, generate new using refresh token if needed
        return tokens
    else:
        flask_app.logger.error("No tokens for user {}.".format(user_email))
        return None

def refresh_tokens_for_user(user_email):
    tokens = get_tokens_for_user(user_email)
    integration_api = WebexTeamsAPI()
    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
    try:
        new_tokens = AccessTokenAbs(integration_api.access_tokens.refresh(client_id, client_secret, tokens.refresh_token).json_data)
        save_tokens(user_email, new_tokens)
        flask_app.logger.info("Tokens refreshed for user {}".format(user_email))
    except ApiError as e:
        flask_app.logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error refreshing an access token. Client Id and Secret loading error: {}".format(e)
        
    return new_tokens
    
# Flask part of the code

@flask_app.before_first_request
def startup():
    dynamodb, tablename, endpoint_url = ddb_single_table.get_db_env()
    flask_app.logger.debug("Using table {} at {}".format(tablename, endpoint_url))
    db_client = boto3.client("dynamodb", endpoint_url=endpoint_url)
    try:
        response = db_client.describe_table(TableName=tablename)
    except db_client.exceptions.ResourceNotFoundException:
        flask_app.logger.info("table '%s' not found, creating new...", (tablename))
        ddb_single_table.setup()
        
    flask_app.logger.debug("Starting event check...")
    thread_executor.submit(check_events, EVENT_CHECK_INTERVAL, username)

@flask_app.route("/")
def hello():
    return "Hello World!"

@flask_app.route("/authdone", methods=["GET"])
def authdone():
    ## TODO: post the information & help, maybe an event creation form to the 1-1 space with the user
    return "Thank you for providing the authorization. You may close this browser window."

@flask_app.route("/authorize", methods=["GET"])
def authorize():
    myUrlParts = urlparse(request.url)
    full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    flask_app.logger.debug("Authorize redirect URL: {}".format(full_redirect_uri))

    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    redirect_uri = quote(full_redirect_uri, safe="")
    scope = WEBEX_SCOPE
    scope_uri = quote(" ".join(scope), safe="")
    join_url = webex_api.base_url+"authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}".format(client_id, redirect_uri, scope_uri, STATE_CHECK)

    return redirect(join_url)
    
@flask_app.route("/manager", methods=["GET"])
def manager():
    if request.args.get("error"):
        return request.args.get("error_description")
        
    input_code = request.args.get("code")
    check_phrase = request.args.get("state")
    flask_app.logger.debug("Authorization request \"state\": {}, code: {}".format(check_phrase, input_code))

    myUrlParts = urlparse(request.url)
    full_redirect_uri = myUrlParts.scheme + "://" + myUrlParts.netloc + url_for("manager")
    flask_app.logger.debug("Manager redirect URI: {}".format(full_redirect_uri))
    
    try:
        client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
        client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
        tokens = AccessTokenAbs(webex_api.access_tokens.get(client_id, client_secret, input_code, full_redirect_uri).json_data)
        flask_app.logger.debug("Access info: {}".format(tokens))
    except ApiError as e:
        flask_app.logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error issuing an access token. Client Id and Secret loading error: {}".format(e)
        
    webex_integration_api = WebexTeamsAPI(access_token=tokens.access_token)
    try:
        user_info = webex_integration_api.people.me()
        flask_app.logger.debug("Got user info: {}".format(user_info))
        save_tokens(user_info.emails[0], tokens)
        
        ## TODO: add periodic access token refresh
    except ApiError as e:
        flask_app.logger.error("Error getting user information: {}".format(e))
        return "Error getting your user information: {}".format(e)
        
    return redirect(url_for("authdone"))
    
@flask_app.route("/tokenrefresh", methods=["GET"])
def token_refresh():
    user_id = request.args.get("user_id")
    if user_id is None:
        return "Please provide a user id"
    
    return refresh_token_for_user(user_id)
    
def refresh_token_for_user(user_id):
    tokens = get_tokens_for_user(user_id)
    integration_api = WebexTeamsAPI()
    client_id = os.getenv("WEBEX_INTEGRATION_CLIENT_ID")
    client_secret = os.getenv("WEBEX_INTEGRATION_CLIENT_SECRET")
    try:
        new_tokens = AccessTokenAbs(integration_api.access_tokens.refresh(client_id, client_secret, tokens.refresh_token).json_data)
        save_tokens(user_id, new_tokens)
    except ApiError as e:
        flask_app.logger.error("Client Id and Secret loading error: {}".format(e))
        return "Error refreshing an access token. Client Id and Secret loading error: {}".format(e)
        
    return "token refresh for user {} done".format(user_id)

@flask_app.route("/tokenrefreshall", methods=["GET"])
def token_refresh_all():
    results = ""
    user_tokens = get_db_record_by_secondary_key_list("TOKENS")
    for token in user_tokens:
        flask_app.logger.debug("Refreshing: {} token".format(token["pk"]))
        results += refresh_token_for_user(token["pk"])+"\n"
    
    return results
    
@flask_app.route("/queryevents", methods=["GET"])
def query_events():
    results = ""
    
    return results
    
def check_events(check_interval, username):
    tokens = None
    wxt_client = None
    from_time = datetime.utcnow()
    while True:
        # flask_app.logger.debug("Check events tick.")
        
        if tokens is None:
            tokens = get_tokens_for_user(username)
            if tokens:
                wxt_client = WebexTeamsAPI(access_token=tokens.access_token)
            else:
                flask_app.logger.error("No access tokens for user {}. Authorize the user first.".format(username))
        else:
            token_delta = datetime.fromtimestamp(float(tokens.expires_at)) - datetime.utcnow()
            if token_delta.total_seconds() < SAFE_TOKEN_DELTA:
                flask_app.logger.info("Access token is about to expire, renewing...")
                tokens = refresh_tokens_for_user(username)
                wxt_client = WebexTeamsAPI(access_token=tokens.access_token)
                
                
        if wxt_client:
            try:
                to_time = datetime.utcnow()
                from_stamp = from_time.isoformat()+"Z"
                to_stamp = to_time.isoformat()+"Z"
                flask_app.logger.debug("check interval {} - {}".format(from_stamp, to_stamp))
                event_list = wxt_client.events.list(_from=from_stamp, to=to_stamp)
                for event in event_list:
                    # flask_app.logger.info("{} {} {} by {}".format(event.created, event.resource, event.type, event.data))
                    actor = wxt_client.people.get(event.actorId)
                    
                    # TODO: information logging to an external system
                    flask_app.logger.info("{} {} {} {} by {}".format(event.created, event.resource, event.type, event.data.personEmail, actor.emails[0]))
                from_time = to_time
            except ApiError as e:
                flask_app.logger.error("Events API request error: {}".format(e))

        time.sleep(check_interval)
    
def start_runner():
    def start_loop():
        not_started = True
        while not_started:
            logger.info('In start loop')
            try:
                r = requests.get('http://127.0.0.1:5050/')
                if r.status_code == 200:
                    logger.info('Server started, quiting start_loop')
                    not_started = False
                logger.debug("Status code: {}".format(r.status_code))
            except:
                logger.info('Server not yet started')
            time.sleep(2)

    logger.info('Started runner')
    thread_executor.submit(start_loop)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', help="Set logging level by number of -v's, -v=WARN, -vv=INFO, -vvv=DEBUG")
    parser.add_argument("-u", "--username", type = str, help="Compliance Officer username (e-mail)", required=True)
    parser.add_argument("-r", "--resource", type = str, help="Resource type (messages, memberships), default: all")
    parser.add_argument("-t", "--type", type = str, help="Event type (created, updated, deleted), default: all")
    parser.add_argument("-a", "--actor", type = str, help="Monitored actor id (user's e-mail), default: all")
    
    args = parser.parse_args()
    if args.verbose:
        if args.verbose > 2:
            logging.basicConfig(level=logging.DEBUG)
        elif args.verbose > 1:
            logging.basicConfig(level=logging.INFO)
        if args.verbose > 0:
            logging.basicConfig(level=logging.WARN)
            
    flask_app.logger.info("Logging level: {}".format(logging.getLogger(__name__).getEffectiveLevel()))
    
    flask_app.logger.info("Using database: {} - {}".format(os.getenv("DYNAMODB_ENDPOINT_URL"), os.getenv("DYNAMODB_TABLE_NAME")))
    
    username = args.username
    
    tokens = get_tokens_for_user(username)

    
    start_runner()
    flask_app.run(host="0.0.0.0", port=5050)
