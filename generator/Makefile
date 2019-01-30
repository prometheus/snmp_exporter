# Copyright 2018 The Prometheus Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MIBDIR := mibs

APC_URL        := 'https://download.schneider-electric.com/files?p_File_Name=powernet426.mib'
ARISTA_URL     := https://www.arista.com/assets/data/docs/MIBS
CISCO_URL      := 'ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz'
KEEPALIVED_URL := 'https://raw.githubusercontent.com/acassen/keepalived/master/doc/KEEPALIVED-MIB.txt'
MIKROTIK_URL   := 'http://download2.mikrotik.com/Mikrotik.mib'
PALOALTO_URL   := 'https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip'
SERVERTECH_URL := 'ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib'
SYNOLOGY_URL   := 'https://global.download.synology.com/download/Document/MIBGuide/Synology_MIB_File.zip'
UBNT_DL_URL    := http://dl.ubnt-ut.com/snmp
UBNT_AIROS_URL := https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip
UCD_URL        := http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt


.DEFAULT: all

.PHONY: all
all: mibs

clean:
	rm -v \
		$(MIBDIR)/* \
		$(MIBDIR)/.cisco_v2 \
		$(MIBDIR)/.paloalto_panos \
		$(MIBDIR)/.synology

.PHONY: mibs
mibs: mib-dir \
  $(MIBDIR)/apc-powernet-mib \
  $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB \
  $(MIBDIR)/ARISTA-SMI-MIB \
  $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB \
  $(MIBDIR)/.cisco_v2 \
  $(MIBDIR)/KEEPALIVED-MIB.txt \
  $(MIBDIR)/.paloalto_panos \
  $(MIBDIR)/servertech-sentry3-mib \
  $(MIBDIR)/.synology \
  $(MIBDIR)/UBNT-MIB \
  $(MIBDIR)/UBNT-UniFi-MIB \
  $(MIBDIR)/UBNT-AirMAX-MIB.txt \
  $(MIBDIR)/UCD-SNMP-MIB.txt

mib-dir:
	@mkdir -p -v $(MIBDIR)

$(MIBDIR)/apc-powernet-mib:
	@echo ">> Downloading apc-powernet-mib"
	@curl -s -o $(MIBDIR)/apc-powernet-mib -L $(APC_URL)

$(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB:
	@echo ">> Downloading ARISTA-ENTITY-SENSOR-MIB"
	@curl -s -o $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB -L "$(ARISTA_URL)/ARISTA-ENTITY-SENSOR-MIB.txt"

$(MIBDIR)/ARISTA-SMI-MIB:
	@echo ">> Downloading ARISTA-SMI-MIB"
	@curl -s -o $(MIBDIR)/ARISTA-SMI-MIB -L "$(ARISTA_URL)/ARISTA-SMI-MIB.txt"

$(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB:
	@echo ">> Downloading ARISTA-SW-IP-FORWARDING-MIB"
	@curl -s -o $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB -L "$(ARISTA_URL)/ARISTA-SW-IP-FORWARDING-MIB.txt"

$(MIBDIR)/.cisco_v2:
	@echo ">> Downloading cisco_v2"
	@curl -s -L $(CISCO_URL) \
		| tar -C $(MIBDIR) --strip-components=3 -zxv
	@touch $(MIBDIR)/.cisco_v2

$(MIBDIR)/KEEPALIVED-MIB.txt:
	@echo ">> Downloading keepalived"
	@curl -s -o $(MIBDIR)/KEEPALIVED-MIB.txt -L $(KEEPALIVED_URL)

$(MIBDIR)/mikrotik.mib:
	@echo ">> Downloading mikrotik"
	@curl -s -o $(MIBDIR)/mikrotik.mib -L $(MIKROTIK_URL)

$(MIBDIR)/.paloalto_panos:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading paloalto_pano to $(TMP)"
	@curl -s -o $(TMP) -L $(PALOALTO_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.paloalto_panos

$(MIBDIR)/servertech-sentry3-mib:
	@echo ">> Downloading servertech-sentry3-mib"
	@curl -s -o $(MIBDIR)/servertech-sentry3-mib -L $(SERVERTECH_URL)

$(MIBDIR)/.synology:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading synology to $(TMP)"
	@curl -s -o $(TMP) -L $(SYNOLOGY_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.synology

$(MIBDIR)/UBNT-MIB:
	@echo ">> Downloading UBNT-MIB"
	@curl -s -o $(MIBDIR)/UBNT-MIB -L "$(UBNT_DL_URL)/UBNT-MIB"

$(MIBDIR)/UBNT-UniFi-MIB:
	@echo ">> Downloading UBNT-UniFi-MIB"
	@curl -s -o $(MIBDIR)/UBNT-UniFi-MIB -L "$(UBNT_DL_URL)/UBNT-UniFi-MIB"

$(MIBDIR)/UBNT-AirMAX-MIB.txt:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading ubnt-airos to $(TMP)"
	@curl -s -o $(TMP) -L $(UBNT_AIROS_URL)
	@unzip -j -d $(MIBDIR) $(TMP) UBNT-AirMAX-MIB.txt
	@rm -v $(TMP)

$(MIBDIR)/UCD-SNMP-MIB.txt:
	@echo ">> Downloading UCD-SNMP-MIB.txt"
	@curl -s -o $(MIBDIR)/UCD-SNMP-MIB.txt -L "$(UCD_URL)"
