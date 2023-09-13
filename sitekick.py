import collections
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

domain = 'internet.nl'
probes = {}

# Group the calls to check all modules
for k, v in PROBES.items():
    if v is None:
        continue
    mod, name = v.name.split('.')[-2:]
    probes.setdefault(mod, {})[name] = k


def p(probes=probes, domains=domain):
    result = {}
    if not isinstance(domains, (list, tuple)):
        domains = [domains]
    if not isinstance(probes, (list, tuple)):
        probes = [probes]
    for domain in domains:
        for p in probes:
            result.setdefault(domain, {})[p] = run_probe(p, domain)
    return result


def json_default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    elif isinstance(obj, LabelEnum):
        return f"{obj.__class__.__name__}.{obj.name}: {obj.value}"
    else:
        return str(obj)


import collections.abc


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

pprint(count_score(result))
pprint(main_keys(result))


run_probe('ipv6_web', 'belastingdienst.nl')
# update(result, p([k for k in PROBES if PROBES[k] and 'ipv6_ns' in k], 'belastingdienst.nl'))
# update(result, p([k for k in PROBES if PROBES[k] and 'tls_mail_smtp_starttls' in k], 'yourhosting.nl'))
web_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in ['web', 'ipv6_ns'])]
mail_checks = [k for k in PROBES if PROBES[k] and any(label in k for label in ['mail']) and not 'shared' in k]

result1 = {}
update(result1, p(web_checks, ['internet.nl', 'remedu.nl', 'sitekick.eu', 'belastingdienst.nl']))
p(['web_rpki'], ['internet.nl', 'remedu.nl', 'sitekick.eu', 'belastingdienst.nl'])
p(['web_rpki'], ['internet.nl'])

# update(result, p([k for k in PROBES if PROBES[k] and any(label in k for label in
#                                                         ['dnssec', 'rpki', 'tls', 'ipv6', 'appsecpriv'])],
#                 'sitekick.eu'))
# update(result, p([k for k in PROBES if PROBES[k]], 'google.com'))
update(result1,
       p(web_checks, ['yourhosting.nl', 'nu.nl', 'rabobank.nl', 'belastingdienst.nl', 'xxx.com']))
result1 = {}
update(result1,
       p([k for k in PROBES if PROBES[k]], ['yourhosting.nl', 'nu.nl', 'rabobank.nl', 'belastingdienst.nl', 'xxx.com']))

open('./data/probes-web.json', 'w').write(json.dumps(result1, default=json_default, indent=4))
