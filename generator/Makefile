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

MIBDIR   := mibs
MIB_PATH := 'mibs'

CURL_OPTS ?= -s --retry 3 --retry-delay 3 --compressed --location

DOCKER_IMAGE_NAME ?= snmp-generator
DOCKER_IMAGE_TAG  ?= $(subst /,-,$(shell git rev-parse --abbrev-ref HEAD))
DOCKER_REPO       ?= prom

APC_URL          := 'https://download.schneider-electric.com/files?p_File_Name=powernet428.mib'
ARISTA_URL       := https://www.arista.com/assets/data/docs/MIBS
CISCO_URL        := 'ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz'
FRAMEWORK_URL    := http://www.net-snmp.org/docs/mibs/SNMP-FRAMEWORK-MIB.txt
IANA_CHARSET_URL := https://www.iana.org/assignments/ianacharset-mib/ianacharset-mib
IANA_IFTYPE_URL  := https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
IANA_PRINTER_URL := https://www.iana.org/assignments/ianaprinter-mib/ianaprinter-mib
IPV6_TC_URL      := http://www.net-snmp.org/docs/mibs/IPV6-TC.txt
KEEPALIVED_URL   := 'https://raw.githubusercontent.com/acassen/keepalived/master/doc/KEEPALIVED-MIB.txt'
MIKROTIK_URL     := 'http://download2.mikrotik.com/Mikrotik.mib'
NEC_URL          := https://jpn.nec.com/univerge/ix/Manual/MIB
NET_SNMP_URL     := http://www.net-snmp.org/docs/mibs/NET-SNMP-MIB.txt
NET_TC_URL       := http://www.net-snmp.org/docs/mibs/NET-SNMP-TC.txt
PALOALTO_URL     := 'https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip'
PRINTER_URL      := https://ftp.pwg.org/pub/pwg/pmp/mibs/rfc3805b.mib
SERVERTECH_URL   := 'https://cdn10.servertech.com/assets/documents/documents/817/original/Sentry3.mib'
SYNOLOGY_URL     := 'https://global.download.synology.com/download/Document/MIBGuide/Synology_MIB_File.zip'
UBNT_AIROS_URL   := https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip
UBNT_DL_URL      := http://dl.ubnt-ut.com/snmp
UCD_URL          := http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt

.DEFAULT: all

.PHONY: all
all: mibs

clean:
	rm -v \
		$(MIBDIR)/* \
		$(MIBDIR)/cisco_v2 \
		$(MIBDIR)/.cisco_v2 \
		$(MIBDIR)/.paloalto_panos \
		$(MIBDIR)/.synology

generator: *.go
	go build

generate: generator mibs
	MIBDIRS=$(MIB_PATH) ./generator --fail-on-parse-errors generate

parse_errors: generator mibs
	MIBDIRS=$(MIB_PATH) ./generator --fail-on-parse-errors parse_errors

.PHONY: docker
docker:
	docker build -t "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" .

.PHONY: docker-publish
docker-publish:
	docker push "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME)"

.PHONY: docker-tag-latest
docker-tag-latest:
	docker tag "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):latest"

.PHONY: mibs
mibs: mib-dir \
  $(MIBDIR)/apc-powernet-mib \
  $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB \
  $(MIBDIR)/ARISTA-SMI-MIB \
  $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB \
  $(MIBDIR)/.cisco_v2 \
  $(MIBDIR)/IANA-CHARSET-MIB.txt \
  $(MIBDIR)/IANA-IFTYPE-MIB.txt \
  $(MIBDIR)/IANA-PRINTER-MIB.txt \
  $(MIBDIR)/IPV6-TC \
  $(MIBDIR)/KEEPALIVED-MIB \
  $(MIBDIR)/MIKROTIK-MIB \
  $(MIBDIR)/NET-SNMP-MIB \
  $(MIBDIR)/NET-SNMP-TC \
  $(MIBDIR)/.paloalto_panos \
  $(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt \
  $(MIBDIR)/PICO-SMI-ID-MIB.txt \
  $(MIBDIR)/PICO-SMI-MIB.txt \
  $(MIBDIR)/PRINTER-MIB-V2.txt \
  $(MIBDIR)/servertech-sentry3-mib \
  $(MIBDIR)/SNMP-FRAMEWORK-MIB \
  $(MIBDIR)/.synology \
  $(MIBDIR)/UBNT-MIB \
  $(MIBDIR)/UBNT-UniFi-MIB \
  $(MIBDIR)/UBNT-AirMAX-MIB.txt \
  $(MIBDIR)/UCD-SNMP-MIB.txt

mib-dir:
	@mkdir -p -v $(MIBDIR)

$(MIBDIR)/apc-powernet-mib:
	@echo ">> Downloading apc-powernet-mib"
	@curl $(CURL_OPTS) -o $(MIBDIR)/apc-powernet-mib -L $(APC_URL)

$(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB:
	@echo ">> Downloading ARISTA-ENTITY-SENSOR-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB -L "$(ARISTA_URL)/ARISTA-ENTITY-SENSOR-MIB.txt"

$(MIBDIR)/ARISTA-SMI-MIB:
	@echo ">> Downloading ARISTA-SMI-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-SMI-MIB -L "$(ARISTA_URL)/ARISTA-SMI-MIB.txt"

$(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB:
	@echo ">> Downloading ARISTA-SW-IP-FORWARDING-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB -L "$(ARISTA_URL)/ARISTA-SW-IP-FORWARDING-MIB.txt"

$(MIBDIR)/.cisco_v2:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading cisco_v2"
	@mkdir -p $(MIBDIR)/cisco_v2
	@curl $(CURL_OPTS) -o $(TMP) -L $(CISCO_URL)
	tar --no-same-owner -C $(MIBDIR)/cisco_v2 --strip-components=3 -zxvf $(TMP)
	cp mibs/cisco_v2/AIRESPACE-REF-MIB.my mibs/AIRESPACE-REF-MIB
	cp mibs/cisco_v2/AIRESPACE-WIRELESS-MIB.my mibs/AIRESPACE-WIRELESS-MIB
	cp mibs/cisco_v2/ENTITY-MIB.my mibs/ENTITY-MIB
	cp mibs/cisco_v2/ENTITY-SENSOR-MIB.my mibs/ENTITY-SENSOR-MIB
	cp mibs/cisco_v2/ENTITY-STATE-MIB.my mibs/ENTITY-STATE-MIB
	cp mibs/cisco_v2/ENTITY-STATE-TC-MIB.my mibs/ENTITY-STATE-TC-MIB
	cp mibs/cisco_v2/HOST-RESOURCES-MIB.my mibs/HOST-RESOURCES-MIB
	cp mibs/cisco_v2/IF-MIB.my mibs/IF-MIB
	cp mibs/cisco_v2/INET-ADDRESS-MIB.my mibs/INET-ADDRESS-MIB
	cp mibs/cisco_v2/ISDN-MIB.my mibs/ISDN-MIB
	cp mibs/cisco_v2/SNMPv2-MIB.my mibs/SNMPv2-MIB
	cp mibs/cisco_v2/SNMPv2-SMI.my mibs/SNMPv2-SMI
	cp mibs/cisco_v2/SNMPv2-TC.my mibs/SNMPv2-TC
	@rm -v $(TMP)
	@touch $(MIBDIR)/.cisco_v2

$(MIBDIR)/IANA-CHARSET-MIB.txt:
	@echo ">> Downloading IANA charset MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-CHARSET-MIB.txt -L $(IANA_CHARSET_URL)

$(MIBDIR)/IANA-IFTYPE-MIB.txt:
	@echo ">> Downloading IANA ifType MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-IFTYPE-MIB.txt -L $(IANA_IFTYPE_URL)

$(MIBDIR)/IANA-PRINTER-MIB.txt:
	@echo ">> Downloading IANA printer MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-PRINTER-MIB.txt -L $(IANA_PRINTER_URL)

$(MIBDIR)/IPV6-TC:
	@echo ">> Downloading IPV6-TC"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IPV6-TC -L $(IPV6_TC_URL)

$(MIBDIR)/KEEPALIVED-MIB:
	@echo ">> Downloading KEEPALIVED-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/KEEPALIVED-MIB -L $(KEEPALIVED_URL)

$(MIBDIR)/MIKROTIK-MIB:
	@echo ">> Downloading MIKROTIK-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/MIKROTIK-MIB -L $(MIKROTIK_URL)

$(MIBDIR)/NET-SNMP-MIB:
	@echo ">> Downloading NET-SNMP-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/NET-SNMP-MIB -L $(NET_SNMP_URL)

$(MIBDIR)/NET-SNMP-TC:
	@echo ">> Downloading NET-SNMP-TC"
	@curl $(CURL_OPTS) -o $(MIBDIR)/NET-SNMP-TC -L $(NET_TC_URL)

$(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt:
	@echo ">> Downloading PICO-IPSEC-FLOW-MONITOR-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt -L "$(NEC_URL)/PICO-IPSEC-FLOW-MONITOR-MIB.txt"

$(MIBDIR)/PICO-SMI-MIB.txt:
	@echo ">> Downloading PICO-SMI-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-SMI-MIB.txt -L "$(NEC_URL)/PICO-SMI-MIB.txt"

$(MIBDIR)/PICO-SMI-ID-MIB.txt:
	@echo ">> Downloading PICO-SMI-ID-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-SMI-ID-MIB.txt -L "$(NEC_URL)/PICO-SMI-ID-MIB.txt"

$(MIBDIR)/.paloalto_panos:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading paloalto_pano to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) -L $(PALOALTO_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.paloalto_panos

$(MIBDIR)/PRINTER-MIB-V2.txt:
	@echo ">> Downloading Printer MIB v2"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PRINTER-MIB-V2.txt -L $(PRINTER_URL)

$(MIBDIR)/servertech-sentry3-mib:
	@echo ">> Downloading servertech-sentry3-mib"
	@curl $(CURL_OPTS) -o $(MIBDIR)/servertech-sentry3-mib -L $(SERVERTECH_URL)

$(MIBDIR)/SNMP-FRAMEWORK-MIB:
	@echo ">> Downloading SNMP-FRAMEWORK-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/SNMP-FRAMEWORK-MIB -L $(FRAMEWORK_URL)

$(MIBDIR)/.synology:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading synology to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) -L $(SYNOLOGY_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.synology

$(MIBDIR)/UBNT-MIB:
	@echo ">> Downloading UBNT-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-MIB -L "$(UBNT_DL_URL)/UBNT-MIB"

$(MIBDIR)/UBNT-UniFi-MIB:
	@echo ">> Downloading UBNT-UniFi-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-UniFi-MIB -L "$(UBNT_DL_URL)/UBNT-UniFi-MIB"

$(MIBDIR)/UBNT-AirMAX-MIB.txt:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading ubnt-airos to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) -L $(UBNT_AIROS_URL)
	@unzip -j -d $(MIBDIR) $(TMP) UBNT-AirMAX-MIB.txt
	@rm -v $(TMP)

$(MIBDIR)/UCD-SNMP-MIB.txt:
	@echo ">> Downloading UCD-SNMP-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UCD-SNMP-MIB.txt -L "$(UCD_URL)"
