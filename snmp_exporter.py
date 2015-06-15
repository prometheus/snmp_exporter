import yaml

from pysnmp.entity.rfc3413.oneliner import cmdgen

from prometheus_client import Metric,CollectorRegistry,generate_latest



def walk_oids(host, port, oids):
  cmdGen = cmdgen.CommandGenerator()
  errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(
    cmdgen.CommunityData('public'),
    cmdgen.UdpTransportTarget((host, port)),
    0, 25,
    *oids
    )
  if errorIndication:
    print(errorIndication)
    return
  elif errorStatus:
    print('%s at %s' % (
        errorStatus.prettyPrint(),
        errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'
        )
    )
    return

  for varBindTableRow in varBindTable:
    for name, val in varBindTableRow:
      yield name, val

def parse_indexes(suboid, config):
  labels = {}
  for index in config:
    if index['type'] == 'Integer32':
      labels[index['labelname']] = str(suboid[0])
      suboid = suboid[1:]
  if suboid:
    raise ValueError('Indexes left over')
  return labels


if __name__ == '__main__':
  config = yaml.safe_load(open('config'))

  metrics = {}
  for metric in config['metrics']:
    metrics[metric['name']] = Metric(metric['name'], 'SNMP OID {0}'.format(metric['oid']), 'untyped')

  values = walk_oids('192.168.1.2', 161, config['walk'])
  for oid, value in values:
    oid = tuple(oid)
    for metric in config['metrics']:
      prefix = tuple([int(x) for x in metric['oid'].split('.')])
      if oid[:len(prefix)] == prefix:
        value = float(value)
        indexes = oid[len(prefix):]
        labels = parse_indexes(indexes, metric['indexes'])
        metrics[metric['name']].add_sample(metric['name'], value=value, labels=labels)

  class Collector():
    def collect(self):
      return metrics.values()

  registry = CollectorRegistry()
  registry.register(Collector())
  print(generate_latest(registry))


