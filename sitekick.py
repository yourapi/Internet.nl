import datetime
import json
import os
import sys

from enumfields import Enum as LabelEnum
from enum import Enum

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "internetnl.settings")
# Do one call to initialize Django and Celery
from django.core.management import execute_from_command_line

execute_from_command_line(['manage.py', 'probe', '--probe=ipv6_ns', '--domain=internet.nl'])
# execute_from_command_line(['manage.py', 'probe', '--probe=tls_web_cert', '--domain=internet.nl'])
from interface.management.commands.probe import run_probe, PROBES

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


result = json.load(open('./data/probes.json'))

update(result, p([k for k in PROBES if PROBES[k] and 'ipv6' in k], 'sitekick.eu'))
# update(result, p([k for k in PROBES if PROBES[k]], 'internet.nl'))

# update(result, p([k for k in PROBES if PROBES[k] and any(label in k for label in
#                                                         ['dnssec', 'rpki', 'tls', 'ipv6', 'appsecpriv'])],
#                 'sitekick.eu'))
# update(result, p([k for k in PROBES if PROBES[k]], 'google.com'))
update(result,
       p([k for k in PROBES if PROBES[k]], ['yourhosting.nl', 'nu.nl', 'rabobank.nl', 'belastingdienst.nl', 'xxx.com']))
# update(result, p([k for k in PROBES if PROBES[k] and 'tls_mail_smtp_starttls' in k], ['yourhosting.nl', 'nu.nl', 'rabobank.nl','belastingdienst.nl', 'xxx.com'][2:3]))

open('./data/probes.json', 'w').write(json.dumps(result, default=json_default, indent=4))
