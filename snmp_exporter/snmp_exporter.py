import itertools
import urlparse
import yaml
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from SocketServer import ForkingMixIn

from pysnmp.entity.rfc3413.oneliner import cmdgen
from prometheus_client import Metric, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST, Gauge



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
  return generate_latest(registry)


class ForkingHTTPServer(ForkingMixIn, HTTPServer):
  pass


class SnmpExporterHandler(BaseHTTPRequestHandler):
  def do_GET(self):
    url = urlparse.urlparse(self.path)
    if url.path == '/metrics':
      params = urlparse.parse_qs(url.query)
      if 'address' not in params:
        self.send_response(400)
        self.end_headers()
        self.wfile.write("Missing 'address' from parameters")
        return
      config = yaml.safe_load(open('config'))
      output = collect_snmp(config, params['address'][0])
      self.send_response(200)
      self.send_header('Content-Type', CONTENT_TYPE_LATEST)
      self.end_headers()
      self.wfile.write(output)
    elif url.path == '/':
      self.send_response(200)
      self.end_headers()
      self.wfile.write("""<html>
      <head><title>SNMP Exporter</title></head>
      <body>
      <h1>SNMP Exporter</h1>
      <p>Visit <code>/metrics?address=1.2.3.4</code> to use.</p>
      </body>
      </html>""")
    else:
      self.send_response(404)
      self.end_headers()


if __name__ == '__main__':
  server = ForkingHTTPServer(('', 9116), SnmpExporterHandler)
  server.serve_forever()

