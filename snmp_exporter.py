from pysnmp.entity.rfc3413.oneliner import cmdgen

from prometheus_client import Metric,CollectorRegistry,generate_latest

cmdGen = cmdgen.CommandGenerator()


def scrape_table(host, port, table):
  errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(
    cmdgen.CommunityData('public'),
    cmdgen.UdpTransportTarget((host, port)),
    0, 25,
    table,
    lookupNames=True, lookupValues=True)
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

  # Indexes -> oid -> value
  result = {}

  for varBindTableRow in varBindTable:
    for name, val in varBindTableRow:
      name = str(name)
      if not name.startswith(table + '.'): break
      suffix = name[len(table) + 1:]
      oid, indexes = suffix.split('.', 1)
      result.setdefault(indexes, {})[oid] = val

  return result



if __name__ == '__main__':
  config = { 'baseOid': '1.3.6.1.2.1.2.2.1',
    'indexLengths': [1],
    'indexLabelNames': ['interface'],
    'indexLabelValues': [{'nameFromOid': '2'}],
    'metrics' : [
        { 'name': 'interface_in_octets',
          'oid': '10'
        },
        { 'name': 'interface_out_octets',
          'oid': '11'
        },
      ]
  }

  table = scrape_table('localhost', 161, config['baseOid'])

  metrics = {}
  for metric in config['metrics']:
    metrics[metric['name']] = Metric(metric['name'], 'SNMP OID {0}.{1}'.format(config['baseOid'], metric['oid']), 'gauge')

  for indexes, item in table.items():
    #TODO:Handle more than one index
    labels = {config['indexLabelNames'][0]: str(item[config['indexLabelValues'][0]['nameFromOid']])}
    for metric in config['metrics']:
      metrics[metric['name']].add_sample(metric['name'], labels, item[metric['oid']])

  class Collector():
    def collect(self):
      return metrics.values()

  registry = CollectorRegistry()
  registry.register(Collector())
  print(generate_latest(registry))


