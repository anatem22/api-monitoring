#!/usr/bin/env python3

import json, yaml, os, time

from types import SimpleNamespace
from datetime import date, datetime
from threading import Thread
from keycloak.keycloak_openid import KeycloakOpenID

import prometheus_client
import requests
import hvac
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import logging

#os.environ['no_proxy'] = '*'
EXPORTER_PORT = 8080
CONFIG_PATH = "list.json"
logging.basicConfig(
    format='%(levelname) -5s %(asctime)s %(funcName)- -20s: %(message)s',
    datefmt='%d-%b-%y %H:%M:%S',
    level=logging.INFO)

log = logging.getLogger(__name__)

with open(CONFIG_PATH) as f:
    config = json.loads(f.read(), object_hook=lambda d: SimpleNamespace(**d))

# Prometheus metric objects
APP_METRIC_PREFIX = 'api_probe'
http_requests_completed = prometheus_client.Counter(
    name=f'{APP_METRIC_PREFIX}_http_requests_completed',
    documentation='number of HTTP requests sent with server response',
    labelnames=('method', 'target', 'service_name', 'status_code'))
http_requests_errors = prometheus_client.Counter(
    name=f'{APP_METRIC_PREFIX}_http_requests_errors',
    documentation='number of HTTP requests sent without server response',
    labelnames=('method', 'target','service_name', 'type'))
latency_histogram = prometheus_client.Histogram(
    name=f'{APP_METRIC_PREFIX}_latency_seconds',
    documentation='bucketed groups of round-trip latencies',
    labelnames=('method', 'target', 'service_name'))
http_requests_status_code = prometheus_client.Gauge(
    name=f'{APP_METRIC_PREFIX}_status_code',
    documentation='status_code',
    labelnames=('method', 'target', 'service_name', 'description'))
http_requests_response_errors = prometheus_client.Gauge(
    name=f'{APP_METRIC_PREFIX}_response_errors',
    documentation='response_error',
    labelnames=('method', 'target', 'service_name', 'description'))    

class ServiceMonitor:
    def __init__(self, service_prop):
        self.prop = service_prop
        self.is_updated = False

        self.secret = None
        self.token = None
        self.syspass = None
        self.thread = Thread(target=self.main)
        self.thread.start()

    def main(self):
        while True:
            try:
                self.checkAPI()
            except Exception as e:
                print("Exception ", self.prop.name, e)
                pass
            time.sleep(self.prop.period)

    def secretGetVault(self):
        try:
            vault_token = open(self.prop.vault.token).read()
            client = hvac.Client(url=self.prop.vault.server)
            client.auth.kubernetes.login(self.prop.vault.role, vault_token)
            self.secret=client.read(self.prop.vault.path)
        except:
            self.secret = None
        return self.secret

    def sysPassGet(self):
        try:
            body = { "jsonrpc": "2.0","method": "account/viewPass", "params": { "authToken": self.prop.syspass.token, "tokenPass": self.prop.syspass.token_pass, "id": self.prop.syspass.passWord }, "id": 1 }
            acc_info = requests.post(self.prop.syspass.api, json=body)
            res = acc_info.json()
            passw = json.dumps(res["result"]["result"]["password"])
        except:
            passw = None
        return  passw.replace('"', r'')


    def tokenGet(self):
        try:
            keycloak_openid = KeycloakOpenID(server_url=self.prop.auth.server, client_id=self.prop.auth.client, realm_name=self.prop.auth.realm)
            try:
                if self.token:
                    r_token=json.dumps(self.token["refresh_token"]).replace('"', r'')
                    self.token=keycloak_openid.refresh_token(refresh_token=r_token)
                    log.info(f'Getting refresh_token keycloack for ServiceName: {self.prop.name}')
                else:
                    self.token=keycloak_openid.token(self.prop.auth.username, self.prop.auth.password)
                    log.info(f'Getting access_token keycloack for ServiceName: {self.prop.name}')
            except:
                 self.token=keycloak_openid.token(self.prop.auth.username, self.prop.auth.password)
        except:
            self.token={"access_token": "null"}
        return json.dumps( self.token["access_token"]).replace('"', r'')

    def checkAPI(self):
        data = {}
        files = {}
        json_data = {}
        auth_token = None

        #getting secrets for Vault
        if hasattr(self.prop, "vault"):
            if not self.secret:
                if self.prop.vault.type == "kubernetes":
                    self.secret=self.secretGetVault()
                    self.prop.auth.username = self.secret['data'][self.prop.vault.keys.username]
                    self.prop.auth.password = self.secret['data'][self.prop.vault.keys.password]
            else:
                self.prop.auth.username = self.secret['data'][self.prop.vault.keys.username]
                self.prop.auth.password = self.secret['data'][self.prop.vault.keys.password]
                log.info(f'Getting authorization secrets from the cache . ServiceName: {self.prop.name}')

        #getting password for Syspass
        if hasattr(self.prop, "syspass"):
            if not self.syspass:
                self.syspass=self.sysPassGet()
                self.prop.auth.username = self.prop.syspass.userName
                self.prop.auth.password = self.syspass
            else:
                self.prop.auth.username = self.prop.syspass.userName
                self.prop.auth.password = self.syspass
                log.info(f'Getting authorization password from the cache . ServiceName: {self.prop.name}')

        #getting access token for keycloack
        if hasattr(self.prop, "auth"):
            if self.prop.auth.type == "keycloak":
                auth_token = self.tokenGet()
                headers={'Authorization': 'Bearer ' + auth_token}
            elif self.prop.auth.type == "token":
                auth_token = self.prop.auth.token
                headers={'Authorization': 'Token  ' + auth_token}
            else:
                print("Authorization error")
        
        self.prop.url = f'{self.prop.host}/{self.prop.path}'
        endpoint = self.prop.path
        now = time.time()
        response = None
        
        if hasattr(self.prop, "proxy"):
            #self.https_proxy=os.environ.get('HTTPS_PROXY')
            #self.http_proxy=os.environ.get('HTTP_PROXY')
            proxies = {"http": self.prop.proxy.http, "https": self.prop.proxy.https,}
        else:
            proxies = {"http": None, "https": None,}

        try:
            # Send request to endpoint
            if self.prop.method == "POST":
                #body for POST request
                if hasattr(self.prop, "body"):
                    if hasattr(self.prop.body, "json"):
                        json_data =json.loads(self.prop.body.json)
                response = requests.post(self.prop.url, data=data, json=json_data, files=files, headers=headers, proxies=proxies, verify=False, timeout=20 )
            elif self.prop.method == "GET":
                response = requests.get(self.prop.url, headers=headers, proxies=proxies, verify=False, timeout=20)
                # Assuming no errors in the request itself, count the type of result
            http_requests_completed.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, status_code=response.status_code).inc()
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(response.status_code)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
                # Track latency only for completed requests
            latency = time.time() - now
            latency_histogram.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint).observe(latency)
            log.info(f'Response API . Service Name:{self.prop.name}  Status Code:{response.status_code} Duration:{response.elapsed}')
        except requests.exceptions.HTTPError:
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, type='http').inc()
            #if response:
            #    http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(          
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name:{self.prop.name}  Error :"HTTPError"')  
        except requests.exceptions.ConnectionError:
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, type='connection').inc()
            if response:
                http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set()
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name:{self.prop.name}  Error :"ConnectionError"')            
        except requests.exceptions.TooManyRedirects:
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, type='redirects').inc()
            #if response:
            #    http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set()
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name:{self.prop.name}  Error :"TooManyRedirects"')  
        except requests.exceptions.Timeout:
            latency = time.time() - now            
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, type='timeout').inc()
            #if response:
            #    http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set()
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name: {self.prop.name}  Error : "Timeout":{latency}')
        except requests.exceptions.RequestException:
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, type='request').inc()
            #if response:
            #    http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set()
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name:{self.prop.name}  Error :"RequestException"') 
        except Exception:
            http_requests_errors.labels(method=self.prop.method, service_name=self.prop.name, target=endpoint, type='unknown').inc()
            #if response:
            #    http_requests_status_code.remove(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set()
            http_requests_status_code.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(0)
            http_requests_response_errors.labels(method=self.prop.method, service_name=self.prop.name, target=self.prop.url, description=self.prop.description).set(1)
            log.error(f'Response API . Service Name:{self.prop.name}  Error :"Exception"') 
#        if response.status_code:
#            print(datetime.now().strftime("%d.%b %Y %H:%M:%S"),self.prop.name + " -> " + self.prop.method + " -> " + str(response.status_code))
#        else:
#            print(datetime.now().strftime("%d.%b %Y %H:%M:%S"),self.prop.name + " -> " + self.prop.method + " -> " + "error")

inherited_properties = ["period", "auth", "vault", "proxy", "syspass" ]

for group in config.groups:
    for service in group.services:
            for key in inherited_properties:
                if not hasattr(service, key) and hasattr(group, key):
                    setattr(service, key, getattr(group, key))
            ServiceMonitor(service)
            log.info(f'Start service check Service Name: {service.name}')            
            time.sleep(5)

prometheus_client.start_http_server(EXPORTER_PORT)
