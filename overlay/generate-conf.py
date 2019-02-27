#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import ipaddress
import json
import os
from urllib.parse import urlparse

nginx_conf_template = """log_format {site}-default '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" DEFAULT';
log_format {site}-other '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" OTHER';
log_format {site}-local '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" LOCAL';
log_format {site}-remote '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" REMOTE';

server {lb}
    resolver {dns} ipv6={ipv6};

    # listen on ssl
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name {site}.{main_domain};
    root /srv/{site}/data;
    index index.html index.htm;

    ssl on;
    ssl_certificate /certs/fullchain.pem;
    ssl_certificate_key /certs/privkey.pem;
    # enables all versions of TLS, but not SSLv2 or 3 which are weak and now deprecated.
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    # disables all weak ciphers
    ssl_ciphers 'AES128+EECDH:AES128+EDH';
    ssl_prefer_server_ciphers on;

    access_log /srv/{site}/logs/access.log {site}-default;
    error_log /srv/{site}/logs/error.log;

{mirror_config}
    location / {lb}
        proxy_next_upstream error timeout http_404;
        proxy_pass {mirror_scheme_domain}$request_uri;
        proxy_redirect off;
        proxy_set_header Host '{mirror_domain}';
        access_log /srv/{site}/logs/access.log {site}-other;
    {rb}

    location @mirror {lb}
        proxy_store on;
        proxy_store_access user:rw group:rw all:r;
        proxy_next_upstream error timeout http_404;
        proxy_pass {mirror_scheme_domain}$request_uri;
        proxy_redirect off;
        proxy_set_header Host '{mirror_domain}';
        access_log /srv/{site}/logs/access.log {site}-remote;
    {rb}
{rb}
"""

nginx_mirror_config_template = """    location {mirror_path} {lb}
        try_files $uri @mirror;
        access_log /srv/{site}/logs/access.log {site}-local;
    {rb}

"""


# generate nginx configuration based on given config
class NginxConfGenerator(object):
    def __init__(self, json_config):
        try:
            with open(json_config, 'r') as data:
                self.config = json.load(data)
        except:
            raise RuntimeError("{} is invaild or not exists, please check!".format(json_config))

    @staticmethod
    def _check_site_config(site, site_config):
        # check `mirror` parameter
        mirror = site_config.get('mirror', None)
        if mirror == None:
            raise RuntimeError("site `{}` did NOT specify a mirror URL".format(site))

        if mirror[:7] != 'http://' and mirror[:8] != 'https://':
            raise RuntimeError("the mirror URL of site `{}` should start with `http://` or `https://`".format(site))

        parsed_mirror = urlparse(mirror)
        if len(parsed_mirror.netloc) == 0:
            raise RuntimeError("the mirror URL of site `{}` is wrong".format(site))
        site_config['mirror'] = mirror
        site_config['mirror_domain'] = "{}".format(parsed_mirror.netloc)
        site_config['mirror_scheme_domain'] = "{}://{}".format(parsed_mirror.scheme, parsed_mirror.netloc)

        # check whether to enable IPv6, default is False
        ipv6 = site_config.get('ipv6', False)
        if type(ipv6) != bool:
            raise RuntimeError("site `{}` had a non-boolean value for IPv6".format(site))
        if ipv6:
            site_config['ipv6'] = 'on'
        else:
            site_config['ipv6'] = 'off'

        # check DNS, default is 8.8.8.8
        dns = site_config.get('dns', '8.8.8.8')
        try:
            parsed_dns = ipaddress.ip_address(dns)
            site_config['dns'] = "{}".format(parsed_dns)
        except:
            raise RuntimeError("site `{}` had an invalid value for DNS".format(site))

    def generate(self):
        if type(self.config) != dict:
            raise RuntimeError("[ERROR] {} does NOT conform to the required format!".format(json_config))

        main_domain = self.config.get('main_domain', None)
        if main_domain == None:
            raise RuntimeError("[ERROR] {} does NOT specify its main domain".format(json_config))

        mirrors = self.config.get('mirrors', None)
        if type(mirrors) != dict:
            raise RuntimeError("[ERROR] {} does NOT conform to the required format!".format(json_config))
#        start_sh = open('/start.sh', 'w')
#        start_sh.write('#!/bin/sh\n\n')
#        start_sh.write('rm /etc/nginx/sites-enabled/default\n')
        for site, site_config in mirrors.items():
            NginxConfGenerator._check_site_config(site, site_config)
            with open('/etc/nginx/sites-enabled/{}'.format(site), 'w') as site_config_file:
                nginx_mirror_configs = None
                mirror_path = site_config['mirror_path']
                if type(mirror_path) == str:
                    nginx_mirror_configs = nginx_mirror_config_template.format(lb='{', rb='}', 
                        mirror_path=mirror_path, 
                        site=site)
                elif type(mirror_path) == list:
                    nginx_mirror_configs = []
                    for path in mirror_path:
                        if type(path) != str:
                            raise RuntimeError("[ERROR] {} does NOT conform to the required format!".format(json_config))
                        nginx_mirror_configs.append(nginx_mirror_config_template.format(lb='{', rb='}', 
                            mirror_path=path,
                            site=site))
                    nginx_mirror_configs = "".join(nginx_mirror_configs)
                else:
                    raise RuntimeError("[ERROR] {} does NOT conform to the required format!".format(json_config))

                site_config_file.write(nginx_conf_template.format(lb='{', rb='}',
                    site=site,
                    main_domain=main_domain,
                    ipv6=site_config['ipv6'],
                    dns=site_config['dns'],
                    mirror_config=nginx_mirror_configs,
                    mirror_domain=site_config['mirror_domain'],
                    mirror_scheme_domain=site_config['mirror_scheme_domain']
                ))
            start_sh.write('mkdir -p /srv/{}/logs\n'.format(site))
            start_sh.write('touch /srv/{}/logs/access.log\n'.format(site))
            start_sh.write('touch /srv/{}/logs/error.log\n'.format(site))
            print('[INFO] site `{}` config created successfully'.format(site))
        start_sh.write('nginx -g "daemon off;"\n')
        start_sh.close()


if __name__ == '__main__':
    nginx_conf_gen = NginxConfGenerator('config.json')
    nginx_conf_gen.generate()
