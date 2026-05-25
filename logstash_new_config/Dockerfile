FROM opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0

# Install SNMP input plugin (required for Eltex SNMP polling pipeline)
RUN logstash-plugin install logstash-input-snmp
