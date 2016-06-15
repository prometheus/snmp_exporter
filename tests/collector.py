import unittest

from snmp_exporter.collector import parse_indexes

class TestCollector(unittest.TestCase):


  def test_parse_indexes(self):
    oids = {(1, 2, 3, 4): 'eth0', (1, 3, 65, 32, 255): 'octet',
            (1, 1, 4, 10, 181, 1, 30): 'ipv4',
            (1, 2, 16, 42, 6, 29, 128, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 1, 52):
            'ipv6'}
    self.assertEqual({}, parse_indexes((), [], [], oids))
    self.assertEqual({'l': '4'},
        parse_indexes((4,), [{'labelname': 'l', 'type': 'Integer32'}], [], oids))
    self.assertEqual({'l': 'eth0'},
        parse_indexes((4,), [{'labelname': 'l', 'type': 'Integer32'}],
                      [{'labels': ['l'], 'labelname': 'l', 'oid': '1.2.3'}], oids))
    self.assertEqual({'a': '3', 'b': '4', 'l': 'eth0'},
        parse_indexes((3, 4,), [{'labelname': 'a', 'type': 'Integer32'}, {'labelname': 'b', 'type': 'Integer32'}],
                      [{'labels': ['a', 'b'], 'labelname': 'l', 'oid': '1.2'}], oids))
    self.assertEqual({'l': '0'},
        parse_indexes((), [{'labelname': 'l', 'type': 'Integer32'}], [], {}))
    self.assertEqual({'l': '01:FF:00:00:00:10'},
        parse_indexes((1, 255, 0, 0, 0, 16), [{'labelname': 'l', 'type': 'PhysAddress48'}],
                      [], {}))
    self.assertEqual({'l': 'octet'},
        parse_indexes((3, 65, 32, 255), [{'labelname': 'l', 'type': 'OctetString'}],
                      [{'labels': ['l'], 'labelname': 'l', 'oid': '1'}], oids))
    self.assertEqual({'l': 'ipv4'},
        parse_indexes((1, 4, 10, 181, 1, 30), [{'labelname': 'l', 'type': 'InetAddress'}],
                      [{'labels': ['l'], 'labelname': 'l', 'oid': '1'}], oids))
    self.assertEqual({'l': '192.168.2.2'},
        parse_indexes((1, 4, 192, 168, 2, 2), [{'labelname': 'l', 'type': 'InetAddress'}],
                      [], oids))
    self.assertEqual({'l': 'ipv6'},
        parse_indexes((2, 16, 42, 6, 29, 128, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 1, 52), [{'labelname': 'l', 'type': 'InetAddress'}],
                      [{'labels': ['l'], 'labelname': 'l', 'oid': '1'}], oids))
    self.assertEqual({'l': '2A:06:1D:80:00:01:00:03:00:00:00:00:00:01:01:34'},
        parse_indexes((2, 16, 42, 6, 29, 128, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 1, 52), [{'labelname': 'l', 'type': 'InetAddress'}],
                      [], oids))
