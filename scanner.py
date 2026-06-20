#!/usr/bin/env python3
"""
VulnScan - Website Vulnerability Scanner
A CLI tool for detecting technologies and their CVEs on a target website.
"""

import sys
import re
import json
import time
import socket
import argparse
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────
#  ANSI COLOR CODES  (no external deps needed)
# ─────────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
C  = "\033[96m"   # cyan
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{C}{BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RST}{DIM}              Website Technology & CVE Scanner 
"""

# ─────────────────────────────────────────────
#  TECHNOLOGY FINGERPRINTS
#  Each entry: regex pattern → (tech_name, version_group_index)
# ─────────────────────────────────────────────
HEADER_FINGERPRINTS = {
    # Header name → list of (pattern, tech, version_capture_group)
    "server": [
        (r"Apache(?:/([\d.]+))?",          "Apache HTTP Server", 1),
        (r"nginx(?:/([\d.]+))?",            "nginx",             1),
        (r"Microsoft-IIS(?:/([\d.]+))?",    "Microsoft IIS",     1),
        (r"LiteSpeed(?:/([\d.]+))?",        "LiteSpeed",         1),
        (r"openresty(?:/([\d.]+))?",        "OpenResty",         1),
        (r"cloudflare",                     "Cloudflare",        None),
        (r"Caddy(?:/([\d.]+))?",            "Caddy",             1),
        (r"Tomcat(?:/([\d.]+))?",           "Apache Tomcat",     1),
        (r"Jetty(?:/([\d.]+))?",            "Eclipse Jetty",     1),
        (r"gunicorn(?:/([\d.]+))?",         "Gunicorn",          1),
        (r"waitress(?:/([\d.]+))?",         "Waitress",          1),
        (r"Node\.js",                       "Node.js",           None),
        (r"lighttpd(?:/([\d.]+))?",         "Lighttpd",          1),
    ],
    "x-powered-by": [
        (r"PHP(?:/([\d.]+))?",              "PHP",               1),
        (r"ASP\.NET(?:\s+([\d.]+))?",       "ASP.NET",           1),
        (r"Express(?:/([\d.]+))?",          "Express.js",        1),
        (r"Next\.js",                       "Next.js",           None),
        (r"Servlet(?:/([\d.]+))?",          "Java Servlet",      1),
        (r"Ruby on Rails",                  "Ruby on Rails",     None),
        (r"Django",                         "Django",            None),
        (r"Laravel",                        "Laravel",           None),
        (r"Nuxt\.js",                       "Nuxt.js",           None),
    ],
    "x-generator": [
        (r"WordPress(?:\s+([\d.]+))?",      "WordPress",         1),
        (r"Drupal\s+([\d.]+)",              "Drupal",            1),
        (r"Joomla!\s+([\d.]+)",             "Joomla",            1),
        (r"Wix",                            "Wix",               None),
        (r"Ghost(?:\s+([\d.]+))?",          "Ghost CMS",         1),
    ],
    "x-aspnet-version": [
        (r"([\d.]+)",                       "ASP.NET",           1),
    ],
    "x-drupal-cache": [
        (r"",                               "Drupal",            None),
    ],
    "x-wp-total": [
        (r"",                               "WordPress",         None),
    ],
    "x-shopify-stage": [
        (r"",                               "Shopify",           None),
    ],
    "cf-ray": [
        (r"",                               "Cloudflare",        None),
    ],
    "x-amz-request-id": [
        (r"",                               "Amazon AWS",        None),
    ],
    "x-azure-ref": [
        (r"",                               "Microsoft Azure",   None),
    ],
    "x-vercel-id": [
        (r"",                               "Vercel",            None),
    ],
    "x-content-type-options": [
        (r"",                               None,                None),  # security header (no tech)
    ],
}

# Patterns to search in HTML body
BODY_FINGERPRINTS = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](WordPress[\s\d.]*)',  "WordPress",       1),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](Drupal\s[\d.]*)',     "Drupal",          1),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](Joomla!\s[\d.]*)',    "Joomla",          1),
    (r'wp-content|wp-includes',                                                    "WordPress",       None),
    (r'/sites/default/files',                                                      "Drupal",          None),
    (r'Powered by <a[^>]+>vBulletin</a>',                                         "vBulletin",       None),
    (r'<script[^>]+src=["\'][^"\']*react(?:\.min)?\.js',                          "React",           None),
    (r'__NEXT_DATA__',                                                             "Next.js",         None),
    (r'__nuxt|__NUXT__',                                                           "Nuxt.js",         None),
    (r'ng-version=["\']([^"\']+)',                                                 "Angular",         1),
    (r'<script[^>]+src=["\'][^"\']*vue(?:\.min)?\.js',                            "Vue.js",          None),
    (r'jQuery v([\d.]+)',                                                          "jQuery",          1),
    (r'jquery(?:\.min)?\.js\?ver=([\d.]+)',                                        "jQuery",          1),
    (r'bootstrap(?:\.min)?\.css\?ver=([\d.]+)',                                    "Bootstrap",       1),
    (r'<link[^>]+bootstrap(?:\.min)?\.css',                                        "Bootstrap",       None),
    (r'Shopify\.theme',                                                            "Shopify",         None),
    (r'Wix\.com Website Builder',                                                  "Wix",             None),
    (r'data-wf-site',                                                              "Webflow",         None),
    (r'squarespace\.com',                                                          "Squarespace",     None),
    (r'cdn\.ghost\.org',                                                           "Ghost CMS",       None),
    (r'laravel_session|laravel_token',                                             "Laravel",         None),
    (r'csrfmiddlewaretoken',                                                       "Django",          None),
    (r'Powered by <a[^>]+>phpBB</a>',                                             "phpBB",           None),
    (r'<script[^>]+src=["\'][^"\']*ember(?:\.min)?\.js',                          "Ember.js",        None),
    (r'window\.__reactFiber|_reactRootContainer',                                  "React",           None),
]

# ─────────────────────────────────────────────
#  STATIC CVE DATABASE
#  Real CVEs sourced from NVD / public records
#  Format: tech_name → list of CVE dicts
# ─────────────────────────────────────────────
CVE_DATABASE = {
    "Apache HTTP Server": [
        {"id": "CVE-2021-41773", "score": 9.8, "severity": "CRITICAL",
         "desc": "Path traversal & RCE in Apache 2.4.49 via mod_cgi. Allows unauthenticated remote code execution.",
         "affects": "2.4.49", "fixed": "2.4.50+"},
        {"id": "CVE-2021-42013", "score": 9.8, "severity": "CRITICAL",
         "desc": "Incomplete fix for CVE-2021-41773 in Apache 2.4.50 still allows path traversal.",
         "affects": "2.4.49-2.4.50", "fixed": "2.4.51+"},
        {"id": "CVE-2022-31813", "score": 9.8, "severity": "CRITICAL",
         "desc": "mod_proxy may forward requests to the origin server without forwarding client IP headers.",
         "affects": "2.4.x < 2.4.54", "fixed": "2.4.54+"},
        {"id": "CVE-2024-38472", "score": 9.1, "severity": "CRITICAL",
         "desc": "SSRF via Windows UNC path in mod_rewrite on Windows systems.",
         "affects": "< 2.4.60", "fixed": "2.4.60+"},
        {"id": "CVE-2023-25690", "score": 9.8, "severity": "CRITICAL",
         "desc": "HTTP request smuggling via mod_proxy in configurations with RewriteRule or ProxyPassMatch.",
         "affects": "2.4.0 – 2.4.55", "fixed": "2.4.56+"},
    ],
    "nginx": [
        {"id": "CVE-2021-23017", "score": 9.4, "severity": "CRITICAL",
         "desc": "1-byte buffer overwrite in nginx DNS resolver. Can be triggered via malicious DNS responses.",
         "affects": "0.6.18 – 1.20.0", "fixed": "1.20.1+"},
        {"id": "CVE-2022-41741", "score": 7.8, "severity": "HIGH",
         "desc": "Memory corruption in nginx ngx_http_mp4_module when processing crafted MP4 files.",
         "affects": "< 1.23.2", "fixed": "1.23.2+"},
        {"id": "CVE-2024-7347", "score": 5.9, "severity": "MEDIUM",
         "desc": "Worker process can read/write to arbitrary memory locations via ngx_http_mp4_module.",
         "affects": "< 1.27.1", "fixed": "1.27.1+"},
    ],
    "PHP": [
        {"id": "CVE-2024-4577", "score": 9.8, "severity": "CRITICAL",
         "desc": "Argument injection vulnerability in PHP on Windows CGI mode. Allows RCE without authentication.",
         "affects": "< 8.1.29, < 8.2.20, < 8.3.8", "fixed": "8.1.29 / 8.2.20 / 8.3.8"},
        {"id": "CVE-2023-3824", "score": 9.8, "severity": "CRITICAL",
         "desc": "Buffer overflow in phar file parsing. Can cause heap corruption and RCE.",
         "affects": "< 8.0.30, < 8.1.22, < 8.2.8", "fixed": "8.0.30 / 8.1.22 / 8.2.8"},
        {"id": "CVE-2022-31628", "score": 7.8, "severity": "HIGH",
         "desc": "Infinite loop in phar file handler can lead to denial of service.",
         "affects": "< 7.4.30, < 8.0.20, < 8.1.7", "fixed": "7.4.30 / 8.0.20 / 8.1.7"},
        {"id": "CVE-2021-21703", "score": 7.0, "severity": "HIGH",
         "desc": "Local privilege escalation in FPM module allows read/write to PHP-FPM master process memory.",
         "affects": "< 7.3.31, < 7.4.24, < 8.0.11", "fixed": "7.3.31 / 7.4.24 / 8.0.11"},
        {"id": "CVE-2019-11043", "score": 9.8, "severity": "CRITICAL",
         "desc": "Buffer underflow in env_path_info in FPM module (nginx + PHP-FPM). Allows RCE.",
         "affects": "< 7.1.33, < 7.2.24, < 7.3.11", "fixed": "7.1.33 / 7.2.24 / 7.3.11"},
    ],
    "WordPress": [
        {"id": "CVE-2024-6386", "score": 9.9, "severity": "CRITICAL",
         "desc": "SSTI in WPML plugin leads to RCE. Affects 4M+ sites with WPML installed.",
         "affects": "WPML < 4.6.13", "fixed": "WPML 4.6.13"},
        {"id": "CVE-2023-2745", "score": 6.4, "severity": "MEDIUM",
         "desc": "Directory traversal via 'wp_lang' parameter allows reading arbitrary files.",
         "affects": "< 6.2.1", "fixed": "6.2.1+"},
        {"id": "CVE-2022-21664", "score": 8.8, "severity": "HIGH",
         "desc": "SQL injection in WP_Query via improper sanitization. Authenticated attackers can extract DB.",
         "affects": "< 5.8.3", "fixed": "5.8.3+"},
        {"id": "CVE-2021-29447", "score": 7.1, "severity": "HIGH",
         "desc": "XXE attack via crafted WAV file media upload leads to SSRF and file disclosure.",
         "affects": "5.6 – 5.7.1", "fixed": "5.7.2+"},
        {"id": "CVE-2019-8942", "score": 8.8, "severity": "HIGH",
         "desc": "Path traversal in Post meta data allows authenticated users to set arbitrary thumbnail paths leading to RCE.",
         "affects": "< 5.0.1", "fixed": "5.0.1+"},
    ],
    "Drupal": [
        {"id": "CVE-2018-7600", "score": 9.8, "severity": "CRITICAL",
         "desc": "Drupalgeddon 2: Remote code execution via multiple subsystems (Form API, AJAX). No auth needed.",
         "affects": "6.x, 7.x < 7.58, 8.x < 8.5.1", "fixed": "7.58 / 8.5.1"},
        {"id": "CVE-2018-7602", "score": 9.8, "severity": "CRITICAL",
         "desc": "Remote code execution via URL alias API. Related to Drupalgeddon 2.",
         "affects": "7.x < 7.59, 8.x < 8.5.3", "fixed": "7.59 / 8.5.3"},
        {"id": "CVE-2019-6340", "score": 8.1, "severity": "HIGH",
         "desc": "RCE via REST API when using HAL+JSON or JSON:API. No auth required with REST enabled.",
         "affects": "8.6.x < 8.6.10", "fixed": "8.6.10+"},
    ],
    "Joomla": [
        {"id": "CVE-2023-23752", "score": 5.3, "severity": "MEDIUM",
         "desc": "Improper access check allows unauthenticated read of REST API endpoints revealing config data.",
         "affects": "4.0.0 – 4.2.7", "fixed": "4.2.8+"},
        {"id": "CVE-2015-8562", "score": 10.0, "severity": "CRITICAL",
         "desc": "Remote code execution via PHP object injection in session handling. Widely exploited in the wild.",
         "affects": "< 3.4.6", "fixed": "3.4.6+"},
        {"id": "CVE-2016-8870", "score": 8.1, "severity": "HIGH",
         "desc": "Privilege escalation via account registration when registration is disabled.",
         "affects": "3.4.4 – 3.6.3", "fixed": "3.6.4+"},
    ],
    "Microsoft IIS": [
        {"id": "CVE-2021-31166", "score": 9.8, "severity": "CRITICAL",
         "desc": "HTTP Protocol Stack RCE. Wormable vulnerability in http.sys. No user interaction required.",
         "affects": "IIS on Windows 10 2004/20H2", "fixed": "KB5003173"},
        {"id": "CVE-2022-21907", "score": 9.8, "severity": "CRITICAL",
         "desc": "Wormable RCE in HTTP Protocol Stack (http.sys) with no user interaction or auth needed.",
         "affects": "Windows 11, Server 2019/2022", "fixed": "January 2022 Patch Tuesday"},
        {"id": "CVE-2017-7269", "score": 9.8, "severity": "CRITICAL",
         "desc": "Buffer overflow in WebDAV service allows RCE via a crafted PROPFIND request.",
         "affects": "IIS 6.0 (Windows Server 2003)", "fixed": "N/A – EOL OS"},
    ],
    "ASP.NET": [
        {"id": "CVE-2023-36899", "score": 8.8, "severity": "HIGH",
         "desc": "Auth bypass in ASP.NET via malformed requests bypassing FormsAuthentication checks.",
         "affects": ".NET Framework 3.5 – 4.8.1", "fixed": "August 2023 Patch"},
        {"id": "CVE-2021-26701", "score": 9.8, "severity": "CRITICAL",
         "desc": "RCE in .NET Core and .NET 5 via crafted web request in ASP.NET Core.",
         "affects": ".NET 5.0 < 5.0.4", "fixed": "5.0.4+"},
        {"id": "CVE-2017-9248", "score": 9.8, "severity": "CRITICAL",
         "desc": "Telerik UI for ASP.NET AJAX: Crypto weakness allows remote file upload and RCE.",
         "affects": "Telerik.Web.UI < 2017.2.621", "fixed": "2017.2.621"},
    ],
    "jQuery": [
        {"id": "CVE-2020-11022", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS via passing HTML containing <option> tags to jQuery's manipulation methods.",
         "affects": "1.2 – 3.4.x", "fixed": "3.5.0+"},
        {"id": "CVE-2020-11023", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS via HTML in jQuery manipulation methods; incomplete fix for CVE-2020-11022.",
         "affects": "1.0.3 – 3.4.x", "fixed": "3.5.0+"},
        {"id": "CVE-2019-11358", "score": 6.1, "severity": "MEDIUM",
         "desc": "Prototype pollution via $.extend() allows modification of Object prototype.",
         "affects": "< 3.4.0", "fixed": "3.4.0+"},
        {"id": "CVE-2015-9251", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS via cross-domain AJAX requests that are given non-JSON content type.",
         "affects": "< 3.0.0", "fixed": "3.0.0+"},
    ],
    "Bootstrap": [
        {"id": "CVE-2024-6484", "score": 6.4, "severity": "MEDIUM",
         "desc": "XSS via data-loading-text attribute in Bootstrap 3.x tooltip/popover components.",
         "affects": "3.x < 3.4.1", "fixed": "3.4.2+"},
        {"id": "CVE-2019-8331", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS in tooltip or popover data-template attribute in Bootstrap.",
         "affects": "3.x < 3.4.1, 4.x < 4.3.1", "fixed": "3.4.1 / 4.3.1"},
        {"id": "CVE-2018-14040", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS via the collapse data-parent attribute in Bootstrap 3 and 4.",
         "affects": "3.x – 4.x < 4.1.2", "fixed": "4.1.2+"},
    ],
    "React": [
        {"id": "CVE-2018-6341", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS through user-controlled attributes using SVG markup; fixed in React 16.0.0.",
         "affects": "< 16.0.0", "fixed": "16.0.0+"},
    ],
    "Next.js": [
        {"id": "CVE-2025-29927", "score": 9.1, "severity": "CRITICAL",
         "desc": "Auth middleware bypass via x-middleware-subrequest header. Allows bypassing all middleware.",
         "affects": "< 14.2.25 / < 15.2.3", "fixed": "14.2.25 / 15.2.3"},
        {"id": "CVE-2024-46982", "score": 7.5, "severity": "HIGH",
         "desc": "Cache poisoning via crafted HTTP request headers in Next.js server.",
         "affects": "< 14.2.10", "fixed": "14.2.10+"},
        {"id": "CVE-2024-34351", "score": 7.5, "severity": "HIGH",
         "desc": "SSRF via Host header manipulation in Next.js server actions.",
         "affects": "13.4.0 – 14.1.0", "fixed": "14.1.1+"},
    ],
    "Angular": [
        {"id": "CVE-2022-25869", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS through iframe sandbox bypass with SVG element in AngularJS.",
         "affects": "AngularJS < 1.8.3", "fixed": "1.8.3+"},
        {"id": "CVE-2020-35873", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS in AngularJS template injection via ng-include and other directives.",
         "affects": "< 1.8.0", "fixed": "1.8.0+"},
    ],
    "Vue.js": [
        {"id": "CVE-2024-6783", "score": 6.4, "severity": "MEDIUM",
         "desc": "DOM clobbering vulnerability in Vue.js SSR renderer allows XSS via prototype manipulation.",
         "affects": "Vue 3.x < 3.4.38", "fixed": "3.4.38+"},
    ],
    "Express.js": [
        {"id": "CVE-2024-43796", "score": 5.0, "severity": "MEDIUM",
         "desc": "XSS via the res.redirect() function when a user-controlled redirect URL is reflected.",
         "affects": "< 4.20.0", "fixed": "4.20.0+"},
        {"id": "CVE-2024-29041", "score": 6.1, "severity": "MEDIUM",
         "desc": "Open redirect via malformed URLs in Express router allows phishing attacks.",
         "affects": "< 4.19.2", "fixed": "4.19.2+"},
    ],
    "Django": [
        {"id": "CVE-2024-27351", "score": 7.5, "severity": "HIGH",
         "desc": "Potential ReDoS via crafted URLs in django.utils.text.Truncator.",
         "affects": "< 4.2.11, < 5.0.3", "fixed": "4.2.11 / 5.0.3"},
        {"id": "CVE-2023-36053", "score": 7.5, "severity": "HIGH",
         "desc": "ReDoS in EmailValidator and URLValidator via specially crafted strings.",
         "affects": "< 3.2.20, < 4.1.10, < 4.2.3", "fixed": "3.2.20 / 4.1.10 / 4.2.3"},
        {"id": "CVE-2021-44420", "score": 7.5, "severity": "HIGH",
         "desc": "Potential bypass of an upstream access control via crafted HTTP requests with URL path.",
         "affects": "< 2.2.25, < 3.1.14, < 3.2.10", "fixed": "2.2.25 / 3.1.14 / 3.2.10"},
    ],
    "Laravel": [
        {"id": "CVE-2021-3129", "score": 9.8, "severity": "CRITICAL",
         "desc": "RCE via Ignition debug mode when APP_DEBUG=true. Log file manipulation leads to RCE.",
         "affects": "< 8.4.2 with Ignition < 2.5.2", "fixed": "8.4.2 / Ignition 2.5.2"},
        {"id": "CVE-2022-40482", "score": 6.5, "severity": "MEDIUM",
         "desc": "Auth bypass via username manipulation in Laravel Fortify authentication component.",
         "affects": "Fortify < 1.11.1", "fixed": "Fortify 1.11.1+"},
    ],
    "Apache Tomcat": [
        {"id": "CVE-2025-24813", "score": 9.8, "severity": "CRITICAL",
         "desc": "Partial PUT request handling allows deserialization leading to RCE or info disclosure.",
         "affects": "10.1.x < 10.1.35, 11.0.x < 11.0.3", "fixed": "10.1.35 / 11.0.3"},
        {"id": "CVE-2022-42252", "score": 9.1, "severity": "CRITICAL",
         "desc": "Request smuggling via invalid Transfer-Encoding headers if system uses a reverse proxy.",
         "affects": "< 8.5.83, < 9.0.65, < 10.1.1", "fixed": "8.5.83 / 9.0.65 / 10.1.1"},
        {"id": "CVE-2020-1938", "score": 9.8, "severity": "CRITICAL",
         "desc": "Ghostcat – AJP protocol file read/RCE. Connector enabled by default on port 8009.",
         "affects": "< 7.0.100, < 8.5.51, < 9.0.31", "fixed": "7.0.100 / 8.5.51 / 9.0.31"},
    ],
    "Cloudflare": [
        {"id": "CVE-2023-7083", "score": 4.3, "severity": "LOW",
         "desc": "Cloudflare Tunnel improper access control allows data plane disruption.",
         "affects": "cloudflared < 2023.10.0", "fixed": "2023.10.0+"},
    ],
    "Gunicorn": [
        {"id": "CVE-2024-1135", "score": 7.5, "severity": "HIGH",
         "desc": "HTTP request smuggling via Transfer-Encoding header handling. Affects reverse proxy setups.",
         "affects": "< 22.0.0", "fixed": "22.0.0+"},
    ],
    "Ruby on Rails": [
        {"id": "CVE-2024-26143", "score": 5.4, "severity": "MEDIUM",
         "desc": "XSS via the redirect_to helper with user-controlled host values.",
         "affects": "< 7.1.3.1 / < 7.0.8.1", "fixed": "7.1.3.1 / 7.0.8.1"},
        {"id": "CVE-2023-22795", "score": 7.5, "severity": "HIGH",
         "desc": "ReDoS via Query String Parsing in Action Dispatch with crafted HTTP parameters.",
         "affects": "< 7.0.4.1", "fixed": "7.0.4.1+"},
        {"id": "CVE-2022-32224", "score": 9.8, "severity": "CRITICAL",
         "desc": "Possible RCE or DoS via serialization of objects in cookie store (YAML deserialization).",
         "affects": "< 7.0.3.1, < 6.1.6.1, < 6.0.5.1", "fixed": "7.0.3.1 / 6.1.6.1"},
    ],
    "Node.js": [
        {"id": "CVE-2024-27980", "score": 9.8, "severity": "CRITICAL",
         "desc": "Command injection on Windows via improper handling of batch file arguments in child_process.spawn.",
         "affects": "< 18.20.2, < 20.12.2, < 21.7.3", "fixed": "18.20.2 / 20.12.2 / 21.7.3"},
        {"id": "CVE-2023-38552", "score": 7.5, "severity": "HIGH",
         "desc": "Integrity check bypass via hash algorithm inconsistency in policy mechanism.",
         "affects": "< 20.8.1, < 18.18.2", "fixed": "20.8.1 / 18.18.2"},
    ],
    "phpBB": [
        {"id": "CVE-2023-46143", "score": 6.1, "severity": "MEDIUM",
         "desc": "XSS via posting crafted content in phpBB board posts.",
         "affects": "< 3.3.11", "fixed": "3.3.11+"},
    ],
    "Ghost CMS": [
        {"id": "CVE-2023-40028", "score": 8.8, "severity": "HIGH",
         "desc": "Arbitrary file read via symlink attack in theme upload feature. Auth required.",
         "affects": "< 5.59.1", "fixed": "5.59.1+"},
        {"id": "CVE-2024-34448", "score": 9.6, "severity": "CRITICAL",
         "desc": "Privilege escalation from Author to Admin via email address manipulation.",
         "affects": "< 5.82.2", "fixed": "5.82.2+"},
    ],
    "Eclipse Jetty": [
        {"id": "CVE-2023-36479", "score": 4.3, "severity": "MEDIUM",
         "desc": "Incorrect encoding of URI in CGI servlet leads to inadvertent path traversal.",
         "affects": "< 11.0.16, < 10.0.16, < 9.4.53", "fixed": "11.0.16 / 10.0.16 / 9.4.53"},
        {"id": "CVE-2023-26048", "score": 5.3, "severity": "MEDIUM",
         "desc": "OutOfMemoryError in multipart form parsing via crafted Content-Type header (DoS).",
         "affects": "< 11.0.14", "fixed": "11.0.14+"},
    ],
    "Lighttpd": [
        {"id": "CVE-2022-37797", "score": 7.5, "severity": "HIGH",
         "desc": "Out-of-bounds read in lighttpd's h2_send_cqueuelen function allows remote DoS.",
         "affects": "< 1.4.67", "fixed": "1.4.67+"},
    ],
    "LiteSpeed": [
        {"id": "CVE-2022-0073", "score": 8.8, "severity": "HIGH",
         "desc": "Code execution via .htaccess parsing in LiteSpeed Web Server.",
         "affects": "< 5.4.12", "fixed": "5.4.12+"},
    ],
    "OpenResty": [
        {"id": "CVE-2022-24464", "score": 7.5, "severity": "HIGH",
         "desc": "HTTP request smuggling via header rewriting in ngx_lua module.",
         "affects": "< 1.21.4", "fixed": "1.21.4+"},
    ],
    "Webflow": [],
    "Squarespace": [],
    "Shopify": [],
    "Wix": [],
    "Vercel": [],
    "Amazon AWS": [],
    "Microsoft Azure": [],
    "Caddy": [],
    "Nuxt.js": [],
    "Ember.js": [],
}

# ─────────────────────────────────────────────
#  SEVERITY COLORS & RISK BARS
# ─────────────────────────────────────────────
def severity_color(severity: str) -> str:
    return {
        "CRITICAL": R + BOLD,
        "HIGH":     R,
        "MEDIUM":   Y,
        "LOW":      G,
        "INFO":     C,
    }.get(severity.upper(), W)

def score_bar(score: float, width: int = 20) -> str:
    """Visual bar for CVSS score (0-10)."""
    filled = int((score / 10.0) * width)
    color  = R if score >= 9 else (R if score >= 7 else (Y if score >= 4 else G))
    bar    = color + "█" * filled + DIM + "░" * (width - filled) + RST
    return bar

def risk_label(score: float) -> str:
    if score >= 9.0:
        return f"{R}{BOLD}CRITICAL ◀ PATCH NOW{RST}"
    if score >= 7.0:
        return f"{R}HIGH — Immediate action recommended{RST}"
    if score >= 4.0:
        return f"{Y}MEDIUM — Plan remediation soon{RST}"
    return f"{G}LOW — Monitor & update{RST}"

# ─────────────────────────────────────────────
#  UTILITY: Safe HTTP request
# ─────────────────────────────────────────────
def fetch_url(url: str, timeout: int = 10):
    """Fetch URL, return (headers_dict, body_str, final_url, status_code)."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500_000).decode("utf-8", errors="replace")
            return dict(resp.headers), body, resp.geturl(), resp.status
    except urllib.error.HTTPError as e:
        # Still useful: grab headers even on 4xx/5xx
        body = e.read(50_000).decode("utf-8", errors="replace") if e.fp else ""
        return dict(e.headers), body, url, e.code
    except Exception as e:
        return {}, "", url, 0

# ─────────────────────────────────────────────
#  STEP 1: Normalize target URL
# ─────────────────────────────────────────────
def normalize_url(target: str) -> list:
    """Try https first, fall back to http. Return list of URLs to probe."""
    target = target.strip().rstrip("/")
    if target.startswith("http://") or target.startswith("https://"):
        return [target]
    return [f"https://{target}", f"http://{target}"]

# ─────────────────────────────────────────────
#  STEP 2: DNS lookup
# ─────────────────────────────────────────────
def dns_lookup(host: str) -> dict:
    """Resolve hostname to IP address."""
    host = re.sub(r"https?://", "", host).split("/")[0]
    try:
        ip = socket.gethostbyname(host)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "N/A"
        return {"ip": ip, "hostname": hostname, "host": host}
    except socket.gaierror:
        return {"ip": "Unresolved", "hostname": "N/A", "host": host}

# ─────────────────────────────────────────────
#  STEP 3: Detect technologies
# ─────────────────────────────────────────────
def detect_technologies(headers: dict, body: str) -> dict:
    """
    Returns dict: { tech_name: version_or_None }
    """
    found = {}

    # Lowercase all header names for comparison
    lh = {k.lower(): v for k, v in headers.items()}

    for header_name, patterns in HEADER_FINGERPRINTS.items():
        val = lh.get(header_name, "")
        if not val:
            continue
        for (pattern, tech, vg) in patterns:
            if tech is None:
                continue
            m = re.search(pattern, val, re.IGNORECASE)
            if m:
                version = m.group(vg) if (vg and m.lastindex and m.lastindex >= vg) else None
                if tech not in found or (version and found[tech] is None):
                    found[tech] = version

    for (pattern, tech, vg) in BODY_FINGERPRINTS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            version = m.group(vg).strip() if (vg and m.lastindex and m.lastindex >= vg) else None
            # Extract just version number from strings like "WordPress 6.5.2"
            if version:
                vm = re.search(r"([\d]+\.[\d.]+)", version)
                version = vm.group(1) if vm else version
            if tech not in found or (version and found[tech] is None):
                found[tech] = version

    return found

# ─────────────────────────────────────────────
#  STEP 4: Fetch CVEs for detected techs
# ─────────────────────────────────────────────
def get_cves(tech: str) -> list:
    """Return CVE list for a technology from our static database."""
    # Try exact match first, then case-insensitive
    if tech in CVE_DATABASE:
        return CVE_DATABASE[tech]
    for key in CVE_DATABASE:
        if key.lower() == tech.lower():
            return CVE_DATABASE[key]
    return []

# ─────────────────────────────────────────────
#  STEP 5: Check security headers
# ─────────────────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS",            "Enforces HTTPS; prevents protocol downgrade attacks"),
    "content-security-policy":   ("CSP",             "Restricts resource loading; mitigates XSS"),
    "x-content-type-options":    ("X-Content-Type",  "Prevents MIME-type sniffing"),
    "x-frame-options":           ("X-Frame-Options", "Prevents clickjacking via iframe embedding"),
    "referrer-policy":           ("Referrer-Policy", "Controls referrer info sent in requests"),
    "permissions-policy":        ("Permissions-Policy","Restricts browser feature access"),
    "x-xss-protection":          ("X-XSS-Protection","Legacy XSS filter for older browsers"),
}

def check_security_headers(headers: dict) -> dict:
    lh = {k.lower(): v for k, v in headers.items()}
    results = {}
    for h, (label, desc) in SECURITY_HEADERS.items():
        present = h in lh
        results[label] = {"present": present, "desc": desc, "value": lh.get(h, "")}
    return results

# ─────────────────────────────────────────────
#  STEP 6: Compute overall risk score
# ─────────────────────────────────────────────
def compute_risk(tech_cve_map: dict, sec_headers: dict) -> tuple:
    """Return (score_0_to_10, label_str)."""
    max_score = 0.0
    for cves in tech_cve_map.values():
        for c in cves:
            if c["score"] > max_score:
                max_score = c["score"]

    # Deduct points for missing critical security headers
    critical_headers = ["HSTS", "CSP", "X-Content-Type", "X-Frame-Options"]
    missing_critical = sum(1 for h in critical_headers if not sec_headers.get(h, {}).get("present"))
    # Normalize: each missing critical header bumps risk slightly
    header_penalty = missing_critical * 0.3
    final_score = min(10.0, max_score + header_penalty) if max_score > 0 else header_penalty * 2

    if final_score >= 9.0: label = "CRITICAL"
    elif final_score >= 7.0: label = "HIGH"
    elif final_score >= 4.0: label = "MEDIUM"
    elif final_score > 0: label = "LOW"
    else: label = "MINIMAL"

    return round(final_score, 1), label

# ─────────────────────────────────────────────
#  OUTPUT HELPERS
# ─────────────────────────────────────────────
def print_section(title: str):
    width = 70
    print(f"\n{C}{'─' * width}{RST}")
    pad = (width - len(title) - 2) // 2
    print(f"{C}│{RST}{' ' * pad}{BOLD}{title}{RST}{' ' * (width - pad - len(title) - 2)}{C}│{RST}")
    print(f"{C}{'─' * width}{RST}")

def print_kv(key: str, value: str, key_width: int = 22):
    print(f"  {C}{key:<{key_width}}{RST} {value}")

# ─────────────────────────────────────────────
#  MAIN SCAN FUNCTION
# ─────────────────────────────────────────────
def scan(target: str, verbose: bool = False, json_out: bool = False):
    print(BANNER)
    print(f"{DIM}  Target  : {W}{target}{RST}")
    print(f"{DIM}  Started : {W}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}\n")

    # ── Resolve target URL ──────────────────────────────────
    urls = normalize_url(target)
    headers, body, final_url, status_code = {}, "", urls[0], 0

    print(f"  {B}[*]{RST} Connecting to target...")
    for url in urls:
        h, b, fu, sc = fetch_url(url)
        if sc != 0:
            headers, body, final_url, status_code = h, b, fu, sc
            break

    if status_code == 0:
        print(f"  {R}[✘]{RST} Could not connect to {target}. Check the URL and try again.\n")
        sys.exit(1)

    print(f"  {G}[✔]{RST} Connected — Status {W}{status_code}{RST}  Final URL: {W}{final_url}{RST}")

    # ── DNS ─────────────────────────────────────────────────
    host_part = re.sub(r"https?://", "", final_url).split("/")[0]
    dns = dns_lookup(host_part)

    # ── Detect techs ────────────────────────────────────────
    print(f"  {B}[*]{RST} Fingerprinting technologies...")
    techs = detect_technologies(headers, body)
    print(f"  {G}[✔]{RST} Found {W}{len(techs)}{RST} technology/ies\n")

    # ── CVE lookup ──────────────────────────────────────────
    tech_cve_map = {}
    for tech in techs:
        cves = get_cves(tech)
        tech_cve_map[tech] = cves

    # ── Security headers ────────────────────────────────────
    sec_headers = check_security_headers(headers)

    # ── Risk score ──────────────────────────────────────────
    risk_score, risk_level = compute_risk(tech_cve_map, sec_headers)

    # ═══════════════════════════════════════════════════════
    #  DISPLAY RESULTS
    # ═══════════════════════════════════════════════════════

    # ── TARGET INFO ─────────────────────────────────────────
    print_section("TARGET INFORMATION")
    print_kv("URL",         final_url)
    print_kv("HTTP Status", str(status_code))
    print_kv("IP Address",  dns["ip"])
    print_kv("Hostname",    dns["hostname"])
    print_kv("Scan Time",   datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # ── TECH STACK ──────────────────────────────────────────
    print_section("DETECTED TECHNOLOGIES")
    if not techs:
        print(f"  {Y}  No technologies detected. Site may be using custom stack or blocking fingerprinting.{RST}")
    else:
        for tech, version in sorted(techs.items()):
            ver_str = f"{G}{version}{RST}" if version else f"{DIM}version unknown{RST}"
            cve_count = len(tech_cve_map.get(tech, []))
            cve_str = (f"{R}[{cve_count} CVE{'s' if cve_count != 1 else ''}]{RST}"
                       if cve_count else f"{G}[No CVEs in DB]{RST}")
            print(f"  {M}◆{RST} {BOLD}{tech:<28}{RST} v{ver_str}  {cve_str}")

    # ── CVE DETAILS ─────────────────────────────────────────
    print_section("CVE ANALYSIS")
    any_cve = False
    for tech, cves in tech_cve_map.items():
        if not cves:
            continue
        any_cve = True
        print(f"\n  {BOLD}{M}{tech}{RST}")
        print(f"  {'─' * 60}")
        for cve in cves:
            sc  = severity_color(cve["severity"])
            print(f"\n    {B}▸{RST} {BOLD}{cve['id']}{RST}  "
                  f"{sc}[{cve['severity']}]{RST}  CVSS: {W}{cve['score']}/10{RST}")
            print(f"      {score_bar(cve['score'])}")
            print(f"      Risk    : {risk_label(cve['score'])}")
            print(f"      Affects : {Y}{cve['affects']}{RST}")
            print(f"      Fixed   : {G}{cve['fixed']}{RST}")
            print(f"      Detail  : {DIM}{cve['desc']}{RST}")
    if not any_cve:
        print(f"\n  {G}  No CVEs found for detected technologies in the database.{RST}")

    # ── SECURITY HEADERS ────────────────────────────────────
    print_section("SECURITY HEADERS")
    for label, info in sec_headers.items():
        icon  = f"{G}✔{RST}" if info["present"] else f"{R}✘{RST}"
        state = f"{G}PRESENT{RST}" if info["present"] else f"{R}MISSING{RST}"
        val   = f" = {DIM}{info['value'][:60]}{RST}" if (info["present"] and info["value"] and verbose) else ""
        print(f"  {icon} {BOLD}{label:<22}{RST} {state}{val}")
        if not info["present"]:
            print(f"      {DIM}↳ {info['desc']}{RST}")

    # ── OVERALL RISK ────────────────────────────────────────
    print_section("OVERALL RISK ASSESSMENT")
    sc = severity_color(risk_level)
    print(f"\n  {BOLD}Risk Score  :{RST}  {sc}{risk_score}/10{RST}  {score_bar(risk_score)}")
    print(f"  {BOLD}Risk Level  :{RST}  {sc}{BOLD}{risk_level}{RST}")
    total_cves = sum(len(v) for v in tech_cve_map.values())
    print(f"  {BOLD}Total CVEs  :{RST}  {W}{total_cves}{RST}")

    critical = sum(1 for v in tech_cve_map.values() for c in v if c["severity"] == "CRITICAL")
    high     = sum(1 for v in tech_cve_map.values() for c in v if c["severity"] == "HIGH")
    medium   = sum(1 for v in tech_cve_map.values() for c in v if c["severity"] == "MEDIUM")
    low      = sum(1 for v in tech_cve_map.values() for c in v if c["severity"] == "LOW")

    print(f"\n  {R}{BOLD}CRITICAL: {critical:>3}{RST}   {R}HIGH: {high:>3}{RST}   "
          f"{Y}MEDIUM: {medium:>3}{RST}   {G}LOW: {low:>3}{RST}")

    # Recommendations
    print(f"\n  {BOLD}Recommendations:{RST}")
    if critical > 0:
        print(f"   {R}•{RST} URGENT: {critical} critical CVE(s) detected. Patch immediately.")
    if high > 0:
        print(f"   {Y}•{RST} HIGH: {high} high-severity CVE(s). Schedule patching within 72 hours.")
    missing_hdr = [l for l, i in sec_headers.items() if not i["present"]]
    if missing_hdr:
        print(f"   {Y}•{RST} Add missing security headers: {', '.join(missing_hdr)}")
    if not any_cve and not missing_hdr:
        print(f"   {G}•{RST} No critical issues found in scanned technologies. Keep software updated.")

    print(f"\n{C}{'─' * 70}{RST}")
    print(f"  {DIM}Scan complete. Data sourced from NVD CVE database (offline snapshot).{RST}")
    print(f"  {DIM}This tool is for educational/authorized testing only.{RST}\n")

    # ── JSON OUTPUT ─────────────────────────────────────────
    if json_out:
        report = {
            "target": final_url,
            "ip": dns["ip"],
            "status": status_code,
            "technologies": {t: {"version": v, "cves": tech_cve_map.get(t, [])} for t, v in techs.items()},
            "security_headers": sec_headers,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "total_cves": total_cves,
            "scanned_at": datetime.now().isoformat(),
        }
        fname = f"vulnscan_{host_part.replace('.','_')}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  {G}[✔]{RST} JSON report saved → {W}{fname}{RST}\n")

# ─────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="VulnScan — Website Technology & CVE Scanner (College Project)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulnscan.py example.com
  python vulnscan.py https://wordpress.org --verbose
  python vulnscan.py apache.org --json
  python vulnscan.py nginx.org -v -j
        """
    )
    parser.add_argument("target",
        help="Target website (e.g. example.com or https://example.com)")
    parser.add_argument("-v", "--verbose",
        action="store_true",
        help="Show security header values")
    parser.add_argument("-j", "--json",
        action="store_true",
        help="Save JSON report to disk")

    args = parser.parse_args()
    scan(args.target, verbose=args.verbose, json_out=args.json)

if __name__ == "__main__":
    main()
