import itertools
import time

from pysnmp.entity.rfc3413.oneliner import cmdgen
from prometheus_client import Metric, CollectorRegistry, generate_latest, Gauge

def walk_oids(host, port, oids):
  cmdGen = cmdgen.CommandGenerator()
  errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(
    cmdgen.CommunityData('public'),
    cmdgen.UdpTransportTarget((host, port)),
    0, 25,
    *oids
    )
  if errorIndication:
    raise Exception(errorIndication)
  elif errorStatus:
    raise Exception(errorStatus)

  for varBindTableRow in varBindTable:
    for name, val in varBindTableRow:
      yield name, val


def oid_to_tuple(oid):
  """Convert an OID to a tuple of numbers"""
  return tuple([int(x) for x in oid.split('.')])


def parse_indexes(suboid, index_config, lookup_config, oids):
  """Return labels for an oid based on config and table entry."""
  labels = {}
  label_oids = {}
  for index in index_config:
    if index['type'] == 'Integer32':
      sub = suboid[0:1]
      label_oids[index['labelname']] = sub
      labels[index['labelname']] = '.'.join((str(s) for s in sub))
      suboid = suboid[1:]
    elif index['type'] == 'PhysAddress48':
      sub = suboid[0:6]
      label_oids[index['labelname']] = sub
      labels[index['labelname']] = ':'.join((str(s) for s in sub))
      suboid = suboid[6:]
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

  values = walk_oids(host, port, config['walk'])
  oids = {}
  for oid, value in values:
    oids[tuple(oid)] = value

  for oid, value in oids.items():
    for metric in config['metrics']:
      prefix = oid_to_tuple(metric['oid'])
      if oid[:len(prefix)] == prefix:
        value = float(value)
        indexes = oid[len(prefix):]
        labels = parse_indexes(indexes, metric.get('indexes', {}), metric.get('lookups', {}), oids)
        metrics[metric['name']].add_sample(metric['name'], value=value, labels=labels)

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
