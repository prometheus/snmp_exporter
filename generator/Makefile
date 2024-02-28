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

CURL_OPTS ?= -L -sS --retry 3 --retry-delay 3 --fail

REPO_TAG ?= $(shell git rev-parse --abbrev-ref HEAD)

DOCKER_IMAGE_NAME ?= snmp-generator
DOCKER_IMAGE_TAG  ?= $(subst /,-,$(REPO_TAG))
DOCKER_REPO       ?= prom

SANITIZED_DOCKER_IMAGE_TAG := $(subst +,-,$(DOCKER_IMAGE_TAG))

SELINUX_ENABLED := $(shell cat /sys/fs/selinux/enforce 2> /dev/null || echo 0)

ifeq ($(SELINUX_ENABLED),1)
  DOCKER_VOL_OPTS ?= :z
endif

APC_URL           := https://download.schneider-electric.com/files?p_enDocType=Firmware&p_File_Name=powernet451.mib&p_Doc_Ref=APC_POWERNETMIB_451_EN
ARISTA_URL        := https://www.arista.com/assets/data/docs/MIBS
CISCO_URL         := https://raw.githubusercontent.com/cisco/cisco-mibs/2d465cce2de4e67a3561d8e41e4c99b597558d4b/v2
DELL_URL          := https://dl.dell.com/FOLDER11196144M/1/Dell-OM-MIBS-11010_A00.zip
IANA_CHARSET_URL  := https://www.iana.org/assignments/ianacharset-mib/ianacharset-mib
IANA_IFTYPE_URL   := https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
IANA_PRINTER_URL  := https://www.iana.org/assignments/ianaprinter-mib/ianaprinter-mib
KEEPALIVED_URL    := https://raw.githubusercontent.com/acassen/keepalived/v2.2.8/doc/KEEPALIVED-MIB.txt
VRRP_URL          := https://raw.githubusercontent.com/acassen/keepalived/v2.2.8/doc/VRRP-MIB.txt
VRRPV3_URL        := https://raw.githubusercontent.com/acassen/keepalived/v2.2.8/doc/VRRPv3-MIB.txt
KEMP_LM_URL       := https://kemptechnologies.com/files/packages/current/LM_mibs.zip
MIKROTIK_URL      := 'https://box.mikrotik.com/f/a41daf63d0c14347a088/?dl=1'
NEC_URL           := https://jpn.nec.com/univerge/ix/Manual/MIB
NET_SNMP_URL      := https://raw.githubusercontent.com/net-snmp/net-snmp/v5.9/mibs
PALOALTO_URL      := https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/zip/snmp-mib/pan-10-0-snmp-mib-modules.zip
PRINTER_URL       := https://ftp.pwg.org/pub/pwg/pmp/mibs/rfc3805b.mib
SERVERTECH_URL    := 'https://cdn10.servertech.com/assets/documents/documents/817/original/Sentry3.mib'
SERVERTECH4_URL   := 'https://cdn10.servertech.com/assets/documents/documents/815/original/Sentry4.mib'
SYNOLOGY_URL      := 'https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_MIB_File.zip'
UBNT_AIROS_URL    := https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip
UBNT_AIRFIBER_URL := https://dl.ubnt.com/firmwares/airfiber5X/v4.1.0/UBNT-MIB.txt
UBNT_DL_URL       := http://dl.ubnt-ut.com/snmp
RARITAN_URL       := https://cdn.raritan.com/download/PX/v1.5.20/PDU-MIB.txt
RARITAN2_URL      := https://cdn1.raritan.com/download/src-g2/4.0.20/PDU2_MIB_4.0.20_49038.txt
INFRAPOWER_URL    := https://www.austin-hughes.com/wp-content/uploads/2021/05/IPD-03-S-MIB.zip
LIEBERT_URL       := https://www.vertiv.com/globalassets/documents/software/monitoring/lgpmib-win_rev16_299461_0.zip
READYNAS_URL      := https://www.downloads.netgear.com/files/ReadyNAS/READYNAS-MIB.txt
READYDATAOS_URL   := https://www.circitor.fr/Mibs/Mib/R/READYDATAOS-MIB.mib

CYBERPOWER_VERSION := 2.11
CYBERPOWER_URL     := https://dl4jz3rbrsfum.cloudfront.net/software/CyberPower_MIB_v$(CYBERPOWER_VERSION).MIB.zip

EAP_VERSION := 1.0
EAP_URL     := http://static.tp-link.com/EAP_Private_Mibs_$(EAP_VERSION).zip

.DEFAULT: all

.PHONY: all
all: mibs

clean:
	rm -rvf \
		$(MIBDIR)/* \
		$(MIBDIR)/.cisco_v2 \
		$(MIBDIR)/.dell \
		$(MIBDIR)/.net-snmp \
		$(MIBDIR)/.paloalto_panos \
		$(MIBDIR)/.synology \
		$(MIBDIR)/.kemp-lm \
		$(MIBDIR)/readynas \
		$(MIBDIR)/readydataos

generator: *.go
	go build

generate: generator mibs
	MIBDIRS=$(MIB_PATH) ./generator --fail-on-parse-errors generate

parse_errors: generator mibs
	MIBDIRS=$(MIB_PATH) ./generator --fail-on-parse-errors parse_errors

.PHONY: docker
docker:
	docker build --build-arg REPO_TAG="$(REPO_TAG)" -t "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(SANITIZED_DOCKER_IMAGE_TAG)" .

.PHONY: docker-generate
docker-generate: docker mibs
	docker run -v "${PWD}:/opt$(DOCKER_VOL_OPTS)" "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(SANITIZED_DOCKER_IMAGE_TAG)" generate

.PHONY: docker-publish
docker-publish:
	docker push "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(SANITIZED_DOCKER_IMAGE_TAG)"

.PHONY: docker-tag-latest
docker-tag-latest:
	docker tag "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(SANITIZED_DOCKER_IMAGE_TAG)" "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):latest"

mibs: \
  $(MIBDIR)/apc-powernet-mib \
  $(MIBDIR)/readynas \
  $(MIBDIR)/readydataos \
  $(MIBDIR)/AIRESPACE-REF-MIB \
  $(MIBDIR)/AIRESPACE-WIRELESS-MIB \
  $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB \
  $(MIBDIR)/ARISTA-SMI-MIB \
  $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB \
  $(MIBDIR)/.dell \
  $(MIBDIR)/ENTITY-MIB \
  $(MIBDIR)/ENTITY-SENSOR-MIB \
  $(MIBDIR)/ENTITY-STATE-MIB \
  $(MIBDIR)/ENTITY-STATE-TC-MIB \
  $(MIBDIR)/IANA-CHARSET-MIB.txt \
  $(MIBDIR)/IANA-IFTYPE-MIB.txt \
  $(MIBDIR)/IANA-PRINTER-MIB.txt \
  $(MIBDIR)/ISDN-MIB \
  $(MIBDIR)/KEEPALIVED-MIB \
  $(MIBDIR)/VRRP-MIB \
  $(MIBDIR)/VRRPv3-MIB \
  $(MIBDIR)/.kemp-lm \
  $(MIBDIR)/MIKROTIK-MIB \
  $(MIBDIR)/.net-snmp \
  $(MIBDIR)/.paloalto_panos \
  $(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt \
  $(MIBDIR)/PICO-SMI-ID-MIB.txt \
  $(MIBDIR)/PICO-SMI-MIB.txt \
  $(MIBDIR)/PRINTER-MIB-V2.txt \
  $(MIBDIR)/servertech-sentry3-mib \
  $(MIBDIR)/servertech-sentry4-mib \
  $(MIBDIR)/.synology \
  $(MIBDIR)/UBNT-UniFi-MIB \
  $(MIBDIR)/UBNT-AirFiber-MIB \
  $(MIBDIR)/UBNT-AirMAX-MIB.txt \
  $(MIBDIR)/PDU-MIB.txt \
  $(MIBDIR)/PDU2-MIB.txt \
  $(MIBDIR)/Infrapower-MIB.mib \
  $(MIBDIR)/LIEBERT_GP_PDU.MIB \
  $(MIBDIR)/CyberPower.MIB \
  $(MIBDIR)/EAP.MIB \
  $(MIBDIR)/EAP-Client.MIB

$(MIBDIR)/apc-powernet-mib:
	@echo ">> Downloading apc-powernet-mib"
	@curl $(CURL_OPTS) -o $(MIBDIR)/apc-powernet-mib "$(APC_URL)"
	# Workaround to make DisplayString available (#867)
	@sed -i.bak -E 's/(DisplayString[[:space:]]*FROM )RFC1213-MIB/\1SNMPv2-TC/' $(MIBDIR)/apc-powernet-mib
	@rm $(MIBDIR)/apc-powernet-mib.bak

$(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB:
	@echo ">> Downloading ARISTA-ENTITY-SENSOR-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-ENTITY-SENSOR-MIB "$(ARISTA_URL)/ARISTA-ENTITY-SENSOR-MIB.txt"

$(MIBDIR)/ARISTA-SMI-MIB:
	@echo ">> Downloading ARISTA-SMI-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-SMI-MIB "$(ARISTA_URL)/ARISTA-SMI-MIB.txt"

$(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB:
	@echo ">> Downloading ARISTA-SW-IP-FORWARDING-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ARISTA-SW-IP-FORWARDING-MIB "$(ARISTA_URL)/ARISTA-SW-IP-FORWARDING-MIB.txt"

$(MIBDIR)/AIRESPACE-REF-MIB:
	@echo ">> Downloading Cisco AIRESPACE-REF-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/AIRESPACE-REF-MIB "$(CISCO_URL)/AIRESPACE-REF-MIB.my"

$(MIBDIR)/AIRESPACE-WIRELESS-MIB:
	@echo ">> Downloading Cisco AIRESPACE-WIRELESS-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/AIRESPACE-WIRELESS-MIB "$(CISCO_URL)/AIRESPACE-WIRELESS-MIB.my"

$(MIBDIR)/.dell:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading dell to $(TMP)"
	@curl $(CURL_OPTS) -H "User-Agent: snmp_exporter" -o $(TMP) $(DELL_URL)
	@unzip -j -d $(MIBDIR) $(TMP) support/station/mibs/iDRAC-*.mib
	@rm -v $(TMP)
	@touch $(MIBDIR)/.dell

$(MIBDIR)/ENTITY-MIB:
	@echo ">> Downloading Cisco ENTITY-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-MIB "$(CISCO_URL)/ENTITY-MIB.my"

$(MIBDIR)/ENTITY-SENSOR-MIB:
	@echo ">> Downloading Cisco ENTITY-SENSOR-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-SENSOR-MIB "$(CISCO_URL)/ENTITY-SENSOR-MIB.my"

$(MIBDIR)/ENTITY-STATE-MIB:
	@echo ">> Downloading Cisco ENTITY-STATE-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-STATE-MIB "$(CISCO_URL)/ENTITY-STATE-MIB.my"

$(MIBDIR)/ENTITY-STATE-TC-MIB:
	@echo ">> Downloading Cisco ENTITY-STATE-TC-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-STATE-TC-MIB "$(CISCO_URL)/ENTITY-STATE-TC-MIB.my"

$(MIBDIR)/ISDN-MIB:
	@echo ">> Downloading Cisco ISDN-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/ISDN-MIB "$(CISCO_URL)/ISDN-MIB.my"

$(MIBDIR)/IANA-CHARSET-MIB.txt:
	@echo ">> Downloading IANA charset MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-CHARSET-MIB.txt $(IANA_CHARSET_URL)

$(MIBDIR)/IANA-IFTYPE-MIB.txt:
	@echo ">> Downloading IANA ifType MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-IFTYPE-MIB.txt $(IANA_IFTYPE_URL)

$(MIBDIR)/IANA-PRINTER-MIB.txt:
	@echo ">> Downloading IANA printer MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/IANA-PRINTER-MIB.txt $(IANA_PRINTER_URL)

$(MIBDIR)/KEEPALIVED-MIB:
	@echo ">> Downloading KEEPALIVED-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/KEEPALIVED-MIB $(KEEPALIVED_URL)

$(MIBDIR)/VRRP-MIB:
	@echo ">> Downloading VRRP-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/VRRP-MIB $(VRRP_URL)

$(MIBDIR)/VRRPv3-MIB:
	@echo ">> Downloading VRRPv3-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/VRRPv3-MIB $(VRRPV3_URL)

$(MIBDIR)/.kemp-lm:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Kemp LM MIBs to $(TMP)"
	@curl $(CURL_OPTS) -L -o $(TMP) $(KEMP_LM_URL)
	@unzip -j -d $(MIBDIR) $(TMP) *.txt
	# Workaround invalid timestamps.
	@sed -i.bak -E 's/"([0-9]{12})[0-9]{2}Z"/"\1Z"/' $(MIBDIR)/*.RELEASE-B100-MIB.txt
	@rm $(MIBDIR)/*.RELEASE-B100-MIB.txt.bak
	@rm -v $(TMP)
	@touch $(MIBDIR)/.kemp-lm

$(MIBDIR)/MIKROTIK-MIB:
	@echo ">> Downloading MIKROTIK-MIB"
	@curl $(CURL_OPTS) -L -o $(MIBDIR)/MIKROTIK-MIB $(MIKROTIK_URL)

$(MIBDIR)/.net-snmp:
	@echo ">> Downloading NET-SNMP mibs"
	@curl $(CURL_OPTS) -o $(MIBDIR)/HCNUM-TC $(NET_SNMP_URL)/HCNUM-TC.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/HOST-RESOURCES-MIB $(NET_SNMP_URL)/HOST-RESOURCES-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/IF-MIB $(NET_SNMP_URL)/IF-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/IP-MIB $(NET_SNMP_URL)/IP-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/INET-ADDRESS-MIB $(NET_SNMP_URL)/INET-ADDRESS-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/IPV6-TC $(NET_SNMP_URL)/IPV6-TC.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/NET-SNMP-MIB $(NET_SNMP_URL)/NET-SNMP-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/NET-SNMP-TC $(NET_SNMP_URL)/NET-SNMP-TC.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/SNMP-FRAMEWORK-MIB $(NET_SNMP_URL)/SNMP-FRAMEWORK-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/SNMPv2-MIB $(NET_SNMP_URL)/SNMPv2-MIB.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/SNMPv2-SMI $(NET_SNMP_URL)/SNMPv2-SMI.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/SNMPv2-TC $(NET_SNMP_URL)/SNMPv2-TC.txt
	@curl $(CURL_OPTS) -o $(MIBDIR)/UCD-SNMP-MIB $(NET_SNMP_URL)/UCD-SNMP-MIB.txt
	@touch $(MIBDIR)/.net-snmp

$(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt:
	@echo ">> Downloading PICO-IPSEC-FLOW-MONITOR-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt "$(NEC_URL)/PICO-IPSEC-FLOW-MONITOR-MIB.txt"

$(MIBDIR)/PICO-SMI-MIB.txt:
	@echo ">> Downloading PICO-SMI-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-SMI-MIB.txt "$(NEC_URL)/PICO-SMI-MIB.txt"

$(MIBDIR)/PICO-SMI-ID-MIB.txt:
	@echo ">> Downloading PICO-SMI-ID-MIB.txt"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PICO-SMI-ID-MIB.txt "$(NEC_URL)/PICO-SMI-ID-MIB.txt"

$(MIBDIR)/.paloalto_panos:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading paloalto_pano to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(PALOALTO_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.paloalto_panos

$(MIBDIR)/PRINTER-MIB-V2.txt:
	@echo ">> Downloading Printer MIB v2"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PRINTER-MIB-V2.txt $(PRINTER_URL)

$(MIBDIR)/servertech-sentry3-mib:
	@echo ">> Downloading servertech-sentry3-mib"
	@curl $(CURL_OPTS) -o $(MIBDIR)/servertech-sentry3-mib $(SERVERTECH_URL)

$(MIBDIR)/servertech-sentry4-mib:
	@echo ">> Downloading servertech-sentry4-mib"
	@curl $(CURL_OPTS) -o $(MIBDIR)/servertech-sentry4-mib $(SERVERTECH4_URL)

$(MIBDIR)/.synology:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading synology to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(SYNOLOGY_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.synology

$(MIBDIR)/UBNT-UniFi-MIB:
	@echo ">> Downloading UBNT-UniFi-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-UniFi-MIB "$(UBNT_DL_URL)/UBNT-UniFi-MIB"

$(MIBDIR)/UBNT-AirFiber-MIB:
	@echo ">> Downloading UBNT-AirFiber-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-AirFiber-MIB $(UBNT_AIRFIBER_URL)

$(MIBDIR)/UBNT-AirMAX-MIB.txt:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading ubnt-airos to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(UBNT_AIROS_URL)
	@unzip -j -d $(MIBDIR) $(TMP) UBNT-AirMAX-MIB.txt
	@rm -v $(TMP)

$(MIBDIR)/PDU-MIB.txt:
	@echo ">> Downloading Raritan PDU-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PDU-MIB.txt "$(RARITAN_URL)"

$(MIBDIR)/PDU2-MIB.txt:
	@echo ">> Downloading Raritan PDU2-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/PDU2-MIB.txt "$(RARITAN2_URL)"

$(MIBDIR)/Infrapower-MIB.mib:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Infrapower-MIB.mib to $(TMP)"
	@rm -vf $(MIBDIR)/IPD-MIB_Q419V9.mib
	@curl $(CURL_OPTS) -L -o $(TMP) $(INFRAPOWER_URL)
	@unzip -j -d $(MIBDIR) $(TMP) IPD-03-S-MIB_Q320V1.mib
	@mv -v $(MIBDIR)/IPD-03-S-MIB_Q320V1.mib $(MIBDIR)/Infrapower-MIB.mib
	@rm -v $(TMP)

$(MIBDIR)/LIEBERT_GP_PDU.MIB:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading LIEBERT_GP_PDU.MIB to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(LIEBERT_URL)
	@unzip -j -d $(MIBDIR) $(TMP) LIEBERT_GP_PDU.MIB LIEBERT_GP_REG.MIB
	@rm -v $(TMP)

$(MIBDIR)/CyberPower.MIB:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading CyberPower.MIB to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(CYBERPOWER_URL)
	@unzip -j -d $(MIBDIR) $(TMP) CyberPower_MIB_v$(CYBERPOWER_VERSION).MIB
	@mv -v $(MIBDIR)/CyberPower_MIB_v$(CYBERPOWER_VERSION).MIB $@
	# Workaround to make DisplayString available (#867)
	@sed -i.bak -E 's/(DisplayString[[:space:]]*FROM )RFC1213-MIB/\1SNMPv2-TC/' $@
	@rm $@.bak
	@rm -v $(TMP)

$(MIBDIR)/EAP.MIB $(MIBDIR)/EAP-Client.MIB:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading EAP.MIB to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(EAP_URL)
	@unzip -j -d $(MIBDIR) $(TMP) EAP_Private-Mibs_$(EAP_VERSION)/TPLINK.mib EAP_Private-Mibs_$(EAP_VERSION)/EAP/clientMib/client.mib
	@mv -v $(MIBDIR)/TPLINK.mib $(MIBDIR)/EAP.MIB
	@mv -v $(MIBDIR)/client.mib $(MIBDIR)/EAP-Client.MIB
	@rm -v $(TMP)

$(MIBDIR)/readynas:
	@echo ">> Downloading readynas"
	@curl $(CURL_OPTS) -o $(MIBDIR)/readynas "$(READYNAS_URL)"

$(MIBDIR)/readydataos:
	@echo ">> Downloading readydataos"
	@curl $(CURL_OPTS) -o $(MIBDIR)/readydataos "$(READYDATAOS_URL)"
