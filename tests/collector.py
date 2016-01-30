import unittest

from snmp_exporter.collector import parse_indexes

class TestCollector(unittest.TestCase):


  def test_parse_indexes(self):
    oids = {(1, 2, 3, 4): 'eth0'}
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

