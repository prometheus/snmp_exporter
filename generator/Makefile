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
CURL_USER_AGENT ?= -H "User-Agent: snmp_exporter generator"

REPO_TAG ?= $(shell git rev-parse --abbrev-ref HEAD)

DOCKER_IMAGE_NAME ?= snmp-generator
DOCKER_IMAGE_TAG  ?= $(subst /,-,$(REPO_TAG))
DOCKER_REPO       ?= prom

SANITIZED_DOCKER_IMAGE_TAG := $(subst +,-,$(DOCKER_IMAGE_TAG))

SELINUX_ENABLED := $(shell cat /sys/fs/selinux/enforce 2> /dev/null || echo 0)

ifeq ($(SELINUX_ENABLED),1)
  DOCKER_VOL_OPTS ?= :z
endif

APC_URL           := https://download.schneider-electric.com/files?p_Doc_Ref=APC_POWERNETMIB_EN&p_enDocType=Firmware
ARISTA_URL        := https://www.arista.com/assets/data/docs/MIBS
CISCO_URL         := https://raw.githubusercontent.com/cisco/cisco-mibs/f55dc443daff58dfc86a764047ded2248bb94e12/v2
DELL_URL          := https://dl.dell.com/FOLDER11196144M/1/Dell-OM-MIBS-11010_A00.zip
DLINK_URL         := https://ftp.dlink.de/des/des-3200-18/driver_software/DES-3200-18_mib_revC_4-04_all_en_20130603.zip
ELTEX_MES_URL     := https://eltex-co.com/upload/iblock/93c/80760x03yv4m8crugf0b8ab5yo8tel34/mibs_10.3.6.6.zip
DELL_NETWORK_URL  := https://supportkb.dell.com/attachment/ka02R000000I7TFQA0/Current_MIBs_pkb_en_US_1.zip
HPE_URL           := https://downloads.hpe.com/pub/softlib2/software1/pubsw-linux/p1580676047/v229101/upd11.85mib.tar.gz
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
UBNT_AIROS_OLD_URL:= https://raw.githubusercontent.com/pgmillon/observium/refs/heads/master/mibs/FROGFOOT-RESOURCES-MIB
UBNT_AIRFIBER_URL := https://dl.ubnt.com/firmwares/airfiber5X/v4.1.0/UBNT-MIB.txt
UBNT_DL_URL       := http://dl.ubnt-ut.com/snmp
RARITAN_URL       := https://cdn.raritan.com/download/PX/v1.5.20/PDU-MIB.txt
RARITAN2_URL      := https://cdn1.raritan.com/download/src-g2/4.0.20/PDU2_MIB_4.0.20_49038.txt
INFRAPOWER_URL    := https://www.austin-hughes.com/wp-content/uploads/2021/05/IPD-03-S-MIB.zip
LIEBERT_URL       := https://www.vertiv.com/globalassets/documents/software/monitoring/lgpmib-win_rev16_299461_0.zip
READYNAS_URL      := https://www.downloads.netgear.com/files/ReadyNAS/READYNAS-MIB.txt
READYDATAOS_URL   := https://www.downloads.netgear.com/files/GDC/RD5200/READYDATA_MIB.zip
SOPHOS_XG_URL     := https://docs.sophos.com/nsg/sophos-firewall/MIB/SOPHOS-XG-MIB.zip
POWERCOM_URL      := https://www.upspowercom.com/pcm-img/Card-DA807/Upsmate_PCM.mib
TPLINK_DDM        := https://static.tp-link.com/upload/software/2024/202402/20240229/L2-tplinkMibs.zip
CISCO_CUCS_URL    := https://raw.githubusercontent.com/cisco/cisco-mibs/refs/heads/main/ucs-mibs
CISCO_CUCS_URL_v2 := https://raw.githubusercontent.com/cisco/cisco-mibs/refs/heads/main/v2
YAMAHA_URL        := https://www.rtpro.yamaha.co.jp/RT/docs/mib/

CYBERPOWER_VERSION := 2.11
CYBERPOWER_URL     := https://dl4jz3rbrsfum.cloudfront.net/software/CyberPower_MIB_v$(CYBERPOWER_VERSION).MIB.zip

EAP_VERSION := 1.0
EAP_URL     := http://static.tp-link.com/EAP_Private_Mibs_$(EAP_VERSION).zip

# https://apps.juniper.net/mib-explorer/download
JUNIPER_VERSION := 24.4R1.10
JUNIPER_URL := https://www.juniper.net/documentation/software/junos/junos244/juniper-mibs-$(JUNIPER_VERSION).zip

.DEFAULT: all

.PHONY: all
all: mibs

clean:
	rm -rvf \
		$(MIBDIR)/* \
		$(MIBDIR)/.cisco-device \
		$(MIBDIR)/.cisco_v2 \
		$(MIBDIR)/.cisco_imc \
		$(MIBDIR)/.dell \
		$(MIBDIR)/.dlink-mibs \
		$(MIBDIR)/.dell-network \
		$(MIBDIR)/.hpe-mib \
		$(MIBDIR)/.net-snmp \
		$(MIBDIR)/.paloalto_panos \
		$(MIBDIR)/.synology \
		$(MIBDIR)/.sophos_xg \
		$(MIBDIR)/.kemp-lm \
		$(MIBDIR)/.tplinkddm \
		$(MIBDIR)/readynas \
		$(MIBDIR)/readydataos \
		$(MIBDIR)/.eltex-mes \
		$(MIBDIR)/.juniper \
		$(MIBDIR)/.yamaha-rt

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
	docker run --rm -v "${PWD}:/opt$(DOCKER_VOL_OPTS)" "$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(SANITIZED_DOCKER_IMAGE_TAG)" --no-fail-on-parse-errors generate

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
  $(MIBDIR)/iDRAC-SMIv2.mib \
  $(MIBDIR)/.hpe-mib \
  $(MIBDIR)/IANA-CHARSET-MIB.txt \
  $(MIBDIR)/IANA-IFTYPE-MIB.txt \
  $(MIBDIR)/IANA-PRINTER-MIB.txt \
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
  $(MIBDIR)/.sophos_xg \
  $(MIBDIR)/.tplinkddm \
  $(MIBDIR)/UBNT-UniFi-MIB \
  $(MIBDIR)/UBNT-AirFiber-MIB \
  $(MIBDIR)/UBNT-AirMAX-MIB.txt \
  $(MIBDIR)/PDU-MIB.txt \
  $(MIBDIR)/PDU2-MIB.txt \
  $(MIBDIR)/Infrapower-MIB.mib \
  $(MIBDIR)/LIEBERT_GP_PDU.MIB \
  $(MIBDIR)/CyberPower.MIB \
  $(MIBDIR)/EAP.MIB \
  $(MIBDIR)/EAP-Client.MIB \
  $(MIBDIR)/powercom \
  $(MIBDIR)/.cisco_imc \
  $(MIBDIR)/.cisco-device \
  $(MIBDIR)/FROGFOOT-RESOURCES-MIB \
  $(MIBDIR)/.dlink-mibs \
  $(MIBDIR)/.eltex-mes \
  $(MIBDIR)/.juniper \
  $(MIBDIR)/.dell-network \
	$(MIBDIR)/.yamaha-rt

$(MIBDIR)/apc-powernet-mib:
	@echo ">> Downloading apc-powernet-mib" 
	@echo ">> if download fails please check https://www.se.com/at/de/search/?q=powernet+mib&submit+search+query=Search for the latest release"
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

$(MIBDIR)/iDRAC-SMIv2.mib:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading dell to $(TMP)"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(TMP) $(DELL_URL)
	@unzip -j -d $(MIBDIR) $(TMP) support/station/mibs/iDRAC-SMIv2.mib
	@rm -v $(TMP)

$(MIBDIR)/.hpe-mib:
	$(eval TMP := $(shell mktemp))
	$(eval TMP_DIR := $(shell mktemp -d))
	@echo ">> Downloading HPE to $(TMP)"
	@curl -L $(CURL_OPTS) $(CURL_USER_AGENT) -o $(TMP) $(HPE_URL)
	@tar -xf $(TMP) -C $(TMP_DIR)
	@mv $(TMP_DIR)/*cpq*.mib $(MIBDIR)
	@rm -rf $(TMP_DIR) $(TMP)
	@touch $(MIBDIR)/.hpe-mib

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
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/PICO-IPSEC-FLOW-MONITOR-MIB.txt "$(NEC_URL)/PICO-IPSEC-FLOW-MONITOR-MIB.txt"

$(MIBDIR)/PICO-SMI-MIB.txt:
	@echo ">> Downloading PICO-SMI-MIB.txt"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/PICO-SMI-MIB.txt "$(NEC_URL)/PICO-SMI-MIB.txt"

$(MIBDIR)/PICO-SMI-ID-MIB.txt:
	@echo ">> Downloading PICO-SMI-ID-MIB.txt"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/PICO-SMI-ID-MIB.txt "$(NEC_URL)/PICO-SMI-ID-MIB.txt"

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

$(MIBDIR)/.sophos_xg:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Sophos XG to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(SOPHOS_XG_URL)
	@unzip -j -d $(MIBDIR) $(TMP) sophos-xg-mib/SOPHOS-XG-MIB20.txt
	@rm -v $(TMP)
	@touch $(MIBDIR)/.sophos_xg

$(MIBDIR)/.synology:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading synology to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(SYNOLOGY_URL)
	@unzip -j -d $(MIBDIR) $(TMP)
	@rm -v $(TMP)
	@touch $(MIBDIR)/.synology

$(MIBDIR)/.tplinkddm:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading TPLINK Switch DDM to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(TPLINK_DDM)
	@unzip -j -d $(MIBDIR) $(TMP) L2-tplinkMibs/tplink-ddmManage.mib  L2-tplinkMibs/tplink-ddmStatus.mib L2-tplinkMibs/tplink.mib
	@mv $(MIBDIR)/tplink.mib $(MIBDIR)/tplink-main.mib # EAP.MIB contains another incompatible variant of the tplink enterprise mib with same name
	@rm -v $(TMP)
	@touch $(MIBDIR)/.tplinkddm

$(MIBDIR)/UBNT-UniFi-MIB:
	@echo ">> Downloading UBNT-UniFi-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-UniFi-MIB "$(UBNT_DL_URL)/UBNT-UniFi-MIB"

$(MIBDIR)/UBNT-AirFiber-MIB:
	@echo ">> Downloading UBNT-AirFiber-MIB"
	@curl $(CURL_OPTS) -o $(MIBDIR)/UBNT-AirFiber-MIB $(UBNT_AIRFIBER_URL)

$(MIBDIR)/FROGFOOT-RESOURCES-MIB:
	@echo ">> Downloading FROGFOOT-RESOURCES-MIB (UBNT AirOS)"
	@curl $(CURL_OPTS) -o $(MIBDIR)/FROGFOOT-RESOURCES-MIB $(UBNT_AIROS_OLD_URL)

$(MIBDIR)/.dlink-mibs:
	@echo ">> Downloading DLINK mibs"
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading DLINK DES mibs to $(TMP)"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(TMP) $(DLINK_URL)
	@unzip -j -d $(MIBDIR) $(TMP) \
		DES3200_V4.04_MIB_20120906/standardMIB/RMON2-MIB.MIB \
		DES3200_V4.04_MIB_20120906/standardMIB/RMON-MIB.mib \
		DES3200_V4.04_MIB_20120906/standardMIB/token-ring-rmon-mib.MIB \
		DES3200_V4.04_MIB_20120906/standardMIB/P-BRIDGE-MIB.mib \
		DES3200_V4.04_MIB_20120906/standardMIB/BRIDGE-MIB.mib \
		DES3200_V4.04_MIB_20120906/standardMIB/Q-BRIDGE-MIB.mib \
		DES3200_V4.04_MIB_20120906/proprietaryMIB/Dlink-common-mgmt/Genmgmt.mib \
		DES3200_V4.04_MIB_20120906/proprietaryMIB/Dlink-mgmt/DLINK-ID-REC-MIB.mib
	@rm -v $(TMP)
	@touch $(MIBDIR)/.dlink-mibs


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
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading readydataos to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) "$(READYDATAOS_URL)"
	@unzip -j -d $(MIBDIR) $(TMP) READYDATAOS-MIB.txt
	@mv -v $(MIBDIR)/READYDATAOS-MIB.txt $(MIBDIR)/readydataos
	@rm -v $(TMP)

$(MIBDIR)/powercom:
	@echo ">> Downloading powercom"
	@curl $(CURL_OPTS) -o $(MIBDIR)/powercom "$(POWERCOM_URL)"

$(MIBDIR)/.cisco_imc:
	@echo ">> Downloading Cisco UCS"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-UNIFIED-COMPUTING-FAULT-MIB.my "$(CISCO_CUCS_URL)/CISCO-UNIFIED-COMPUTING-FAULT-MIB.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-UNIFIED-COMPUTING-MIB.my "$(CISCO_CUCS_URL)/CISCO-UNIFIED-COMPUTING-MIB.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-UNIFIED-COMPUTING-STORAGE-MIB.my "$(CISCO_CUCS_URL)/CISCO-UNIFIED-COMPUTING-STORAGE-MIB.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-UNIFIED-COMPUTING-TC-MIB.my "$(CISCO_CUCS_URL)/CISCO-UNIFIED-COMPUTING-TC-MIB.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-TC.my "$(CISCO_CUCS_URL_v2)/CISCO-TC.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-SMI.my "$(CISCO_CUCS_URL_v2)/CISCO-SMI.my"
	@touch $(MIBDIR)/.cisco_imc

$(MIBDIR)/.eltex-mes:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Eltex MES device mibs to $(TMP)"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(TMP) $(ELTEX_MES_URL)
	@unzip -j -d $(MIBDIR) $(TMP) fsiss.mib eltex/ELTEX-SMI-ACTUAL.mib eltex/ELTEX-MES-ISS-CPU-UTIL-MIB.mib eltex/ELTEX-MES-ISS-MIB.mib CISCO-QOS-PIB-MIB.mib
	@rm -v $(TMP)
	@touch $(MIBDIR)/.eltex-mes

$(MIBDIR)/.juniper:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Juniper mibs to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(JUNIPER_URL) 
	@unzip -j -d $(MIBDIR) $(TMP) \
		StandardMibs/mib-alarmmib.txt \
		StandardMibs/mib-rfc2819a.txt \
		StandardMibs/mib-rfc4502.txt \
		StandardMibs/mib-rfc1513.txt \
		JuniperMibs/mib-jnx-smi.txt \
		JuniperMibs/mib-jnx-chassis.txt \
		JuniperMibs/mib-jnx-alarm.txt \
		JuniperMibs/mib-jnx-chassis-alarm.txt \
		JuniperMibs/mib-jnx-dom.txt \
		JuniperMibs/mib-jnx-subscriber.txt
	@rm -v $(TMP)
	@touch $(MIBDIR)/.juniper

$(MIBDIR)/.dell-network:
	$(eval TMP := $(shell mktemp))
	@echo ">> Downloading Dell network mibs to $(TMP)"
	@curl $(CURL_OPTS) -o $(TMP) $(DELL_NETWORK_URL)
	@unzip -j -d $(MIBDIR)/dell $(TMP) DELL-NETWORKING-MIB-9.14.2.1.zip
	@unzip -j -d $(MIBDIR) $(MIBDIR)/dell/DELL-NETWORKING-MIB-9.14.2.1.zip \
		DELL-NETWORKING-CHASSIS-MIB.mib \
		DELL-NETWORKING-TC.mib \
		DELL-NETWORKING-SMI.mib
	@rm -rfv $(TMP) $(MIBDIR)/dell
	@touch $(MIBDIR)/.dell-network

# sed below fixes CISCO-FC-FE-MIB mib (ref: https://github.com/cisco/cisco-mibs/issues/136)
$(MIBDIR)/.cisco-device:
	@echo ">> Downloading Cisco device mibs"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-TC $(CISCO_URL)/CISCO-TC.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-SMI $(CISCO_URL)/CISCO-SMI.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-PROCESS-MIB $(CISCO_URL)/CISCO-PROCESS-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ENVMON-MIB $(CISCO_URL)/CISCO-ENVMON-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ENTITY-SENSOR-MIB $(CISCO_URL)/CISCO-ENTITY-SENSOR-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-MEMORY-POOL-MIB $(CISCO_URL)/CISCO-MEMORY-POOL-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-MIB $(CISCO_URL)/ENTITY-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-SENSOR-MIB $(CISCO_URL)/ENTITY-SENSOR-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-STATE-MIB $(CISCO_URL)/ENTITY-STATE-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/ENTITY-STATE-TC-MIB $(CISCO_URL)/ENTITY-STATE-TC-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/ISDN-MIB "$(CISCO_URL)/ISDN-MIB.my"
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-MEMORY-POOL-MIB $(CISCO_URL)/CISCO-MEMORY-POOL-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ENHANCED-MEMPOOL-MIB $(CISCO_URL)/CISCO-ENHANCED-MEMPOOL-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ENTITY-FRU-CONTROL-MIB $(CISCO_URL)/CISCO-ENTITY-FRU-CONTROL-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-FC-FE-MIB $(CISCO_URL)/CISCO-FC-FE-MIB.my
	@sed -i -E 's/OBJECT.+TransceiverPowerControl/OBJECT          fcIfTransceiverPowerControl/' $(MIBDIR)/CISCO-FC-FE-MIB
	@sed -i -E -z 's/(fcIfSysTransceiverPowerControlCapability,\n.+fcIfSysTransceiverPowerControl),/\1/' $(MIBDIR)/CISCO-FC-FE-MIB
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ST-TC $(CISCO_URL)/CISCO-ST-TC.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-VSAN-MIB $(CISCO_URL)/CISCO-VSAN-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ZS-MIB $(CISCO_URL)/CISCO-ZS-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-IF-EXTENSION-MIB $(CISCO_URL)/CISCO-IF-EXTENSION-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-NS-MIB $(CISCO_URL)/CISCO-NS-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-QOS-PIB-MIB $(CISCO_URL)/CISCO-QOS-PIB-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-IMAGE-TC $(CISCO_URL)/CISCO-IMAGE-TC.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-IMAGE-MIB $(CISCO_URL)/CISCO-IMAGE-MIB.my
	@curl $(CURL_OPTS) -o $(MIBDIR)/CISCO-ENHANCED-IMAGE-MIB $(CISCO_URL)/CISCO-ENHANCED-IMAGE-MIB.my
	@touch $(MIBDIR)/.cisco-device

$(MIBDIR)/.yamaha-rt:
	@echo ">> Downloading Yamaha RT Series MIBs"
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-product.mib.txt $(YAMAHA_URL)/yamaha-product.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt.mib.txt $(YAMAHA_URL)/yamaha-rt.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt-firmware.mib.txt $(YAMAHA_URL)/yamaha-rt-firmware.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt-hardware.mib.txt $(YAMAHA_URL)/yamaha-rt-hardware.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt-interfaces.mib.txt $(YAMAHA_URL)/yamaha-rt-interfaces.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt-ip.mib.txt $(YAMAHA_URL)/yamaha-rt-ip.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-rt-switch.mib.txt $(YAMAHA_URL)/yamaha-rt-switch.mib.txt
	@curl $(CURL_OPTS) $(CURL_USER_AGENT) -o $(MIBDIR)/yamaha-smi.mib.txt $(YAMAHA_URL)/yamaha-smi.mib.txt
	# Workaround to make DisplayString available (#867)
	@find $(MIBDIR) -name 'yamaha-*.mib.txt' | xargs sed -i.bak -z -E 's/(DisplayString(, PhysAddress)?[[:space:]\n]*FROM )RFC1213-MIB/\1SNMPv2-TC/'
	@rm $(MIBDIR)/yamaha-*.mib.txt.bak
	@touch $(MIBDIR)/.yamaha-rt
