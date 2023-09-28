import collections
import collections.abc
import datetime
import json
import os
import sys

from pprint import pprint

from enumfields import Enum as LabelEnum
from enum import Enum

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "internetnl.settings")
# Do one call to initialize Django and Celery
from django.core.management import execute_from_command_line

execute_from_command_line(['manage.py', 'probe', '--probe=ipv6_ns', '--domain=internet.nl'])
# execute_from_command_line(['manage.py', 'probe', '--probe=tls_web_cert', '--domain=internet.nl'])
from interface.management.commands.probe import run_probe, PROBES
# PROBES = {}

# from django_redis import get_redis_connection
# print('==== ', get_redis_connection('default'))

OPTIONAL_SCORES = {'http_compression_score', 'client_reneg_score', 'ocsp_stapling_score',
                   'dane_status', 'x_frame_options_score', 'securitytxt_score'}
RECOMMENDED_SCORES = {'kex_hash_func_score', 'dane_score', 'x_content_type_options_score',
                      'content_security_policy_score', 'referrer_policy_score', 'securitytxt_score'}
# Literal copy from okapi.framework yourapi/plugins/internet/website/audit/helpers.py

web_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in {'web', 'ipv6_ns'}) and k not in OPTIONAL_SCORES | RECOMMENDED_SCORES]
mail_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in ['mail']) and not 'shared' in k and k not in OPTIONAL_SCORES | RECOMMENDED_SCORES]


def ensure_key_str(o: object) -> object:
    """Ensure that all keys in a dictionary are strings, recursively."""
    def to_key(key):
        if isinstance(key, Enum):
            return key.name
        elif isinstance(key, (str, int, float, bool)):
            return key
        elif key is None:
            return key
        else:
            return str(key)
    if isinstance(o, dict):
        return {to_key(k): ensure_key_str(v) for k, v in o.items()}
    elif isinstance(o, (list, tuple, set)):
        return type(o)(ensure_key_str(e) for e in o)
    else:
        return o

def transform_probe_result(result):
    """Based on the name of the probe, transform the result to a more readable format."""
    if isinstance(result, tuple) and len(result) > 1 and isinstance(result[0], str):
        if len(result) == 2:
            # probe name followed by result
            return result[-1]
        else:
            # probe name followed by multiple results:
            return list(result[1:])
    return result

def transform_rpki_web(result: dict) -> dict:
    """The rpki returns the result as a list with ip-addresses, instead of a dictionary. Correct this by retrieving
    the ip-addresses from the list."""
    if len(result) != 1:
        return result
    # Single result; get the value, which is a list:
    values = list(result.values())[0]
    if not isinstance(values, list):
        return result
    # The list contains tuples with ip-addresses and a dictionary with the result:
    return {e.get('ip'): {k:v for k,v in e.items() if k != 'ip'} for e in values}


def probe(probes=None, domains: list = None):
    result = {}
    if not (probes and domains):
        return result
    if isinstance(domains, str):
        domains = [domains]
    if isinstance(probes, str):
        probes = [probes]
    for domain in domains:
        domain = domain.strip().lower()
        for p in probes:
            result.setdefault(domain, {})[p] = ensure_key_str(transform_probe_result(run_probe(p, domain)))
            if p == 'web_rpki':
                # Hm, not very elegant; have to refactor later :-((
                result[domain][p] = transform_rpki_web(result[domain][p])
    print('=' * 120)
    pprint(result)
    print('=' * 120)
    if len(domains) > 1:
        return result
    else:
        return result[domains[0]]


def json_default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    elif isinstance(obj, LabelEnum):
        return f"{obj.__class__.__name__}.{obj.name}: {obj.value}"
    else:
        return str(obj)


def update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.abc.Mapping):
            d[k] = update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


try:
    result = json.load(open('./data/probes.json'))
except:
    result = {}

if not isinstance(result, dict):
    result = {}

def count_score(result):
    score_by_domain = collections.Counter()
    def add_scores(domain, tree, accu):
        if isinstance(tree, list):
            for item in tree:
                add_scores(domain, item, accu)
        elif isinstance(tree, dict):
            if 'score' in tree:
                # if tree.get('score') and tree.get('status'):
                accu[domain] += tree['score']
            else:
                for v in tree.values():
                    add_scores(domain, v, accu)
    for domain, scores in result.items():
        add_scores(domain, scores, score_by_domain)
    return score_by_domain

def main_keys(result: dict) -> list:
    """Get the keys from the second level and return in a sorted list."""
    return sorted(set(k for v in result.values() for k in v.keys()))

def tes():
    pprint(count_score(result))
    pprint(main_keys(result))


    run_probe('ipv6_web', 'belastingdienst.nl')
    # update(result, p([k for k in PROBES if PROBES[k] and 'ipv6_ns' in k], 'belastingdienst.nl'))
    # update(result, p([k for k in PROBES if PROBES[k] and 'tls_mail_smtp_starttls' in k], 'yourhosting.nl'))
    web_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in ['web', 'ipv6_ns'])]
    mail_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in ['mail']) and not 'shared' in k]

    result1 = {}
    # update(result1, p(web_checks, ['internet.nl', 'remedu.nl', 'sitekick.eu', 'belastingdienst.nl', 'yourhosting.nl']))
    update(result1, probe(web_checks, ['remedu.nl']))
    probe(['web_rpki'], ['internet.nl', 'remedu.nl', 'sitekick.eu', 'belastingdienst.nl'])
    probe(['web_rpki'], ['internet.nl'])


    open('./data/probes-web.json', 'w').write(json.dumps(result1, default=json_default, indent=4))


from json_sk import JSONEncoder

from flask import Flask
app = Flask(__name__)
app.json_encoder = JSONEncoder

@app.route('/web/<domain>')
def probe_web(domain):
    return probe(web_checks, domain)


@app.route('/probe/<probe_name>/<domain>')
def probe_probe(probe_name, domain):
    return probe(probe_name, domain)
