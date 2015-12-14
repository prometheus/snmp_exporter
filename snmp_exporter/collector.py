import itertools
import time
from easysnmp import Session

from pysnmp.entity.rfc3413.oneliner import cmdgen
from prometheus_client import Metric, CollectorRegistry, generate_latest, Gauge

def walk_oids(host, port, oids, community):

  session = Session(hostname=host, remote_port=port, community=community, version=2, use_numeric=True, use_long_names=True)

  for oid in oids:
      system_items = session.walk(oid)
      for item in system_items:
          yield item.oid[1:]+"."+item.oid_index, str((item.value).encode('ascii', 'ignore'))

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
    elif index['type'] == 'StaticLabel':
      labels[index['labelname']] = index['labelvalue']
    elif index['type'] == 'DynamicLabel':
      full_oid = oid_to_tuple(index['oid'])
      value = oids.get(full_oid)
      if value is not None:
        labels[index['labelname']] = str(value)
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
    prom_type = metric['metric_type'] if 'metric_type' in metric else 'gauge'
    prom_help = metric['metric_help'] if 'metric_help' in metric else 'SNMP OID {0}'.format( metric['oid'] if 'oid' in metric else "NaN" )
    metrics[metric['name']] = Metric(metric['name'], prom_help, prom_type)
  values = walk_oids(host, port, config['walk'], config.get('community', 'public'))
  oids = {}
  for oid, value in values:
    if oid_to_tuple(oid) in oids:
      if ((oids[oid_to_tuple(oid)] is None) and value):
        oids[oid_to_tuple(oid)] = value
    else:
        oids[oid_to_tuple(oid)] = value

  for oid, value in oids.items():
    for metric in config['metrics']:
      prefix = oid_to_tuple(metric['oid'])
      if oid[:len(prefix)] == prefix:
        try:
            value = float(value)
        except ValueError as e:
            print(e)
            value = 0.0

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
