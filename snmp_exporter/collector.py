import binascii
import itertools
import time

import netsnmp

from prometheus_client import Metric, CollectorRegistry, generate_latest, Gauge

def walk_oids(host, port, oids, version, auth):
  if version == 3:
    auth_user = auth['username']
    auth_pass = auth.get('password', '')
    auth_protocol = auth.get('auth_protocol', 'MD5')
    priv_protocol = auth.get('priv_protocol', 'DES')
    priv_pass = auth.get('priv_password', '')
    sec_level = auth.get('security_level', 'noAuthNoPriv')
    session = netsnmp.Session(Version=3, DestHost=host, RemotePort=port,
        SecName=auth_user, AuthPass=auth_pass, AuthProto=auth_protocol,
        PrivProto=priv_protocol, PrivPass=priv_pass, SecLevel=sec_level,
        UseNumeric=True, Retries=3)
  elif version == 2:
    community = auth.get('community', 'public')
    session = netsnmp.Session(Version=2, DestHost=host, RemotePort=port,
        Community=community, UseNumeric=True, Retries=3)
  elif version == 1:
    community = auth.get('community', 'public')
    session = netsnmp.Session(Version=1, DestHost=host, RemotePort=port,
        Community=community, UseNumeric=True, Retries=3)
  for oid in oids:
    for v in walk_oid(session, version, oid):
      yield v

def walk_oid(session, version, oid):
    last_oid = oid
    while True:
      # getbulk starts from the last oid we saw.
      vl = netsnmp.VarList(netsnmp.Varbind('.' + last_oid))
      if version == 1:
        if not session.walk(vl):
          return
      else:
        if not session.getbulk(0, 25, vl):
          return

      for v in vl:
        last_oid = v.tag[1:] + '.' + v.iid
        if not (last_oid + '.').startswith(oid + '.'):
          return
        if v.iid == '0':
          yield v.tag[1:], v.val
        else:
          yield last_oid, v.val

def oid_to_tuple(oid):
  """Convert an OID to a tuple of numbers"""
  return tuple([int(x) for x in oid.split('.')])

def pad_oid(oid, size):
    """If oid is short, pad right with 0s."""
    result = list(oid)
    while len(result) < size:
      result.append(0)
    return result

def parse_indexes(suboid, index_config, lookup_config, oids):
  """Return labels for an oid based on config and table entry."""
  labels = {}
  label_oids = {}
  for index in index_config:
    if index['type'] == 'Integer32':
      sub = pad_oid(suboid[0:1], 1)
      label_oids[index['labelname']] = sub
      labels[index['labelname']] = '.'.join((str(s) for s in sub))
      suboid = suboid[1:]
    elif index['type'] == 'PhysAddress48':
      sub = pad_oid(suboid[0:6], 6)
      label_oids[index['labelname']] = sub
      labels[index['labelname']] = ':'.join(("{0:02X}".format(s) for s in sub))
      suboid = suboid[6:]
    elif index['type'] == 'OctetString':
      length = pad_oid(suboid[0:1], 1)[0]
      content = pad_oid(suboid[1:length+1], length)
      label_oids[index['labelname']] = [length] + content
      labels[index['labelname']] = ''.join((chr(s) for s in content))
      suboid = suboid[length+1:]
    # InetAddress is always formed by [InetAddressType][InetAddressXX] 
    elif index['type'] == 'InetAddress':
      address_type = suboid[0]
      octets = suboid[1:2][0]
      address = suboid[2: 2 + octets]
      label_oids[index['labelname']] = suboid[0: 2 + octets] 
      # ipv4
      if address_type == 1:
        labels[index['labelname']] = '.'.join(str(s) for s in address)
      # ipv6
      elif address_type == 2:
        labels[index['labelname']] = ':'.join(("{0:02X}".format(s) for s in address))   
      suboid = suboid[2 + octets :]

  for lookup in lookup_config:
    index_oid = itertools.chain(*[label_oids[l] for l in lookup['labels']])
    full_oid = oid_to_tuple(lookup['oid']) + tuple(index_oid)
    value = oids.get(full_oid)
    if value is not None:
      labels[lookup['labelname']] = str(value)

  return labels


def collect_snmp(config, host, port=161):
  """Scrape a host and return prometheus text format for it"""

  start = time.time()
  metrics = {}
  for metric in config['metrics']:
    metrics[metric['name']] = Metric(metric['name'], 'SNMP OID {0}'.format(metric['oid']), 'untyped')

  values = walk_oids(host, port, config['walk'], config.get('version', 2), config.get('auth', {}))
  oids = {}
  for oid, value in values:
    if oid != '':
      oids[oid_to_tuple(oid)] = value

  # Netsnmp doesn't tell us if an error has occured, so
  # try to spot it by no results.
  if not oids:
    raise Exception("No OIDs returned, device not responding?")

  # Build a tree from the rules based on oid for faster lookup.
  metric_tree = {}
  for metric in config['metrics']:
    prefix = oid_to_tuple(metric['oid'])
    head = metric_tree
    for i in prefix:
      head.setdefault('children', {})
      head['children'].setdefault(i, {})
      head = head['children'][i]
    head['entry'] = metric

  for oid, value in oids.items():
    head = metric_tree
    for i in oid:
      head = head.get('children', {}).get(i)
      if not head:
        break
      if 'entry' in head:
        metric = head['entry']

        prefix = oid_to_tuple(metric['oid'])
        value = float(value)
        indexes = oid[len(prefix):]
        labels = parse_indexes(indexes, metric.get('indexes', {}), metric.get('lookups', {}), oids)
        metrics[metric['name']].add_sample(metric['name'], value=value, labels=labels)
        break

  class Collector():
    def collect(self):
      return metrics.values()
  registry = CollectorRegistry()
  registry.register(Collector())
  duration = Gauge('snmp_scrape_duration_seconds', 'Time this SNMP scrape took, in seconds', registry=registry)
  duration.set(time.time() - start)
  walked = Gauge('snmp_oids_walked', 'Number of oids walked in this scrape', registry=registry)
  walked.set(len(oids))
  return generate_latest(registry)
