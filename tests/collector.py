import unittest

from snmp_exporter.collector import parse_indexes
from pysnmp.proto.rfc1902 import Counter32, ObjectName, OctetString

class TestCollector(unittest.TestCase):

  def setUp(self):
    self.oids = {ObjectName('1.2.3.4'): OctetString('eth0')}

  def test_parse_indexes(self):
    self.assertEqual({}, parse_indexes((), [], [], self.oids))
    self.assertEqual({'l': '4'}, 
        parse_indexes((4,), [{'labelname': 'l', 'type': 'Integer32'}], [], self.oids))
    self.assertEqual({'l': 'eth0'}, 
        parse_indexes((4,), [{'labelname': 'l', 'type': 'Integer32'}], 
                      [{'labels': ['l'], 'labelname': 'l', 'oid': '1.2.3'}], self.oids))
    self.assertEqual({'a': '3', 'b': '4', 'l': 'eth0'}, 
        parse_indexes((3, 4,), [{'labelname': 'a', 'type': 'Integer32'}, {'labelname': 'b', 'type': 'Integer32'}], 
                      [{'labels': ['a', 'b'], 'labelname': 'l', 'oid': '1.2'}], self.oids))

