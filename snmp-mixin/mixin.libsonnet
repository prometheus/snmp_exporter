{
  grafanaDashboards: {
    'snmp-ubiquiti-wifi.json': (import 'dashboards/snmp_ubiquiti_wifi.json'),
    'snmp-ubiquiti-access_point.json': (import 'dashboards/snmp_ubiquiti_access_point.json'),
  },

  // Helper function to ensure that we don't override other rules, by forcing
  // the patching of the groups list, and not the overall rules object.
  local importRules(rules) = {
    groups+: std.native('parseYaml')(rules)[0].groups,
  },

  prometheusRules+: importRules(importstr 'rules/rules.yaml'),

  prometheusAlerts+:
    importRules(importstr 'alerts/snmp_general.yml') +
    importRules(importstr 'alerts/snmp_ubiquiti_wifi.yml'),
}
