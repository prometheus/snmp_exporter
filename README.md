# SNMP Exporter based on version 0.19.0

This project is an SNMP Exporter based on version 0.19.0 of the original [snmp_exporter](https://github.com/prometheus/snmp_exporter) project. The SNMP Exporter allows you to monitor SNMP-enabled devices by collecting and exposing SNMP metrics to Prometheus.

## About SNMP Exporter

[Prometheus SNMP Exporter](https://github.com/prometheus/snmp_exporter) is an open-source tool that enables the collection and conversion of SNMP metrics into a format that can be scraped by Prometheus. It provides a simple and reliable way to monitor SNMP-enabled devices, such as routers, switches, printers, and other network equipment.

## Version Information

This project is based on version 0.19.0 of the SNMP Exporter. The source code and modifications made for this project are derived from the original release at [https://github.com/prometheus/snmp_exporter/releases/tag/v0.19.0](https://github.com/prometheus/snmp_exporter/releases/tag/v0.19.0).

## Our Purpose
The purpose of this project repository is to extend the capabilities of the SNMP Exporter based on version 0.19.0. Our goal is to provide a flexible and customizable solution that allows us to generate custom binary executable files capable of specifying ports other than the default port 9116. This enhancement empowers us to run multiple SNMP Exporters on the same node, each serving different SNMP-enabled devices or providing specific metrics.

By customizing the SNMP Exporter's port, we gain the ability to segment and manage our SNMP monitoring more efficiently. Each SNMP Exporter instance can focus on specific SNMP devices or metrics, allowing us to collect and analyze data more precisely. This flexibility is especially beneficial in complex environments with a diverse range of network devices, such as routers, switches, printers, and more.

The project's modifications are based on the well-established version 0.19.0 of the SNMP Exporter, which forms a reliable foundation for our enhancements. By leveraging this version as a starting point, we ensure compatibility with existing configurations and maintain the stability and robustness of the SNMP Exporter.

## How to Use
1. In the main.go file, locate the listenAddress variable, and edit it to listen on an unused port by incrementing the port number to the next available one.

2. Edit the Dockerfile to expose the port that the SNMP Exporter is listening on. Update the EXPOSE statement with the port number from step 1.

3. Copy both the updated Dockerfile and the binary executable snmp_exporter to the path within Pando's kubernetes-core repository where the device config lives.

4. Once this is complete, build the Docker image, push it to your Docker Hub repository, and reference your new container image in your Kubernetes deployment YAML.

Note: With these steps, your SNMP Exporter container will now listen on the desired port, and you can deploy it on your Kubernetes cluster with the updated configuration.

## License

This project is licensed under the [Apache License 2.0](LICENSE), the same license used by the original SNMP Exporter project.

## Acknowledgments

This project is built upon the amazing work of the Prometheus team and the contributors to the SNMP Exporter. We extend our gratitude to the open-source community for making this project possible.

For more information on the original SNMP Exporter and its contributors, please visit the [GitHub repository](https://github.com/prometheus/snmp_exporter).

---
*Note: Update the repository URL and other details as necessary based on where you host the code.*