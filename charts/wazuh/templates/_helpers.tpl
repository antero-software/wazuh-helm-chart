{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{- default "wazuh" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wazuh.namespace" -}}
{{- .Release.Namespace }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- $name := default "wazuh" .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.config"}}
server.host: 0.0.0.0
server.port: {{ .Values.dashboard.service.httpPort }}
opensearch.hosts: "https://indexer:{{ .Values.indexer.service.httpPort }}"
opensearch.ssl.verificationMode: none
opensearch.requestHeadersWhitelist: [ authorization,securitytenant ]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.auth.type: ["basicauth","saml"]
opensearch_security.auth.multiple_auth_enabled: true
server.ssl.enabled: {{ .Values.dashboard.enable_ssl }}
server.ssl.key: "/usr/share/wazuh-dashboard/certs/key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/cert.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"]
{{- end }}

{{/* Snippet for the configuration file used by wazuh master */}}
{{- define "wazuh.master.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, master node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>json</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>{{ .Values.wazuh.worker.service.ports.agentEvents }}</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://indexer:{{ .Values.indexer.service.httpPort }}</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
      <enabled>yes</enabled>
      <threads>1</threads>
      <max_sessions>64</max_sessions>
      <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
    <port>{{ .Values.wazuh.master.service.ports.registration }}</port>
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-master-0</node_name>
    <node_type>master</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>wazuh-manager-master-0.wazuh-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  {{- if .Values.wazuh.master.extraConf }}
  {{ .Values.wazuh.master.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}

{{- define "wazuh.master.local_internal_options" }}
# local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.
vulnerability-detection.disable_scan_manager=0
wazuh_modules.debug=0
{{- end }}

{{/* Snippet for the configuration file used by wazuh worker */}}
{{- define "wazuh.worker.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, worker node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>json</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>{{ .Values.wazuh.worker.service.ports.agentEvents }}</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://indexer:{{ .Values.indexer.service.httpPort }}</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
	    <enabled>yes</enabled>
	    <threads>1</threads>
	    <max_sessions>64</max_sessions>
	    <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
    <port>{{ .Values.wazuh.master.service.ports.registration }}</port>
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-worker-___INDEX___</node_name>
    <node_type>worker</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <!-- Kubernetes Service Pointing to Master node -->
        <node>wazuh-manager-master-0.wazuh-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  {{- if .Values.wazuh.worker.extraConf }}
  {{ .Values.wazuh.worker.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}

{{- define "wazuh.worker.local_internal_options" }}
# local_internal_options.conf
#
# This file should be handled with care. It contains
# run time modifications that can affect the use
# of OSSEC. Only change it if you know what you
# are doing. Look first at ossec.conf
# for most of the things you want to change.
#
# This file will not be overwritten during upgrades.
vulnerability-detection.disable_scan_manager=0
wazuh_modules.debug=0
{{- end }}

{{- define "wazuh.indexer.opensearchConfig" }}
cluster.name: ${CLUSTER_NAME}
node.name: ${NODE_NAME}
network.host: ${NETWORK_HOST}
discovery.seed_hosts: {{ include "wazuh.fullname" . }}-indexer-nodes
cluster.initial_master_nodes:
  - {{ include "wazuh.fullname" . }}-indexer-0

node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - CN=admin,O=Company,L=California,C=US
  - CN=filebeat,O=Company,L=California,C=US
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - CN=indexer,O=Company,L=California,C=US
  - CN=filebeat,O=Company,L=California,C=US
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
plugins.security.allow_default_init_securityindex: true
cluster.routing.allocation.disk.threshold_enabled: false
compatibility.override_main_response_version: true
{{- end }}
{{- define "wazuh.extra_rules" }}
<!--
  -  Copyright (C) 2015, Wazuh Inc.
-->

<!--
  SSH rules ID: 5700 - 5764
-->

<group name="syslog,sshd,">

  <rule id="5700" level="0" noalert="1">
    <decoded_as>sshd</decoded_as>
    <description>SSHD messages grouped.</description>
  </rule>

  <rule id="5701" level="8">
    <if_sid>5700</if_sid>
    <match>Bad protocol version identification</match>
    <description>sshd: Possible attack on the ssh server (or version gathering).</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,recon,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5702" level="5">
    <if_sid>5700</if_sid>
    <match>^reverse mapping</match>
    <regex>failed - POSSIBLE BREAK</regex>
    <description>sshd: Reverse lookup error (bad ISP or attack).</description>
    <group>gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5703" level="10" frequency="6" timeframe="360">
    <if_matched_sid>5702</if_matched_sid>
    <same_source_ip />
    <description>sshd: Possible breakin attempt (high number of reverse lookup errors).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5704" level="4">
    <if_sid>5700</if_sid>
    <match>fatal: Timeout before authentication for</match>
    <description>sshd: Timeout while logging in.</description>
  </rule>

  <rule id="5705" level="10" frequency="6" timeframe="360">
    <if_matched_sid>5704</if_matched_sid>
    <description>sshd: Possible scan or breakin attempt (high number of login timeouts).</description>
    <mitre>
      <id>T1190</id>
      <id>T1110</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5706" level="6">
    <if_sid>5700</if_sid>
    <match>Did not receive identification string from</match>
    <description>sshd: insecure connection attempt (scan).</description>
    <mitre>
      <id>T1021.004</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,recon,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5707" level="14">
    <if_sid>5700</if_sid>
    <match>fatal: buffer_get_string: bad string</match>
    <description>sshd: OpenSSH challenge-response exploit.</description>
    <mitre>
      <id>T1210</id>
      <id>T1068</id>
    </mitre>
    <group>exploit_attempt,gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,nist_800_53_SI.2,pci_dss_11.4,pci_dss_6.2,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5709" level="0">
    <if_sid>5700</if_sid>
    <match>error: Could not get shadow information for NOUSER|</match>
    <match>fatal: Read from socket failed: |error: ssh_msg_send: write|</match>
    <match>^syslogin_perform_logout: |^pam_succeed_if(sshd:auth): error retrieving information about user|can't verify hostname: getaddrinfo</match>
    <description>sshd: Useless SSHD message without an user/ip and context.</description>
  </rule>

  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5711" level="0">
    <if_sid>5700</if_sid>
    <match>authentication failure; logname= uid=0 euid=0 tty=ssh|</match>
    <match>input_userauth_request: invalid user|</match>
    <match>PAM: User not known to the underlying authentication module for illegal user|</match>
    <match>error retrieving information about user</match>
    <description>sshd: Useless/Duplicated SSHD message without a user/ip.</description>
  </rule>

  <rule id="5712" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>sshd: brute force trying to get access to the system. Non existent user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5713" level="6">
    <if_sid>5700</if_sid>
    <match>Corrupted check bytes on</match>
    <description>sshd: Corrupted bytes on SSHD.</description>
  </rule>

  <rule id="5714" level="14" timeframe="120" frequency="3">
    <if_matched_sid>5713</if_matched_sid>
    <match>Local: crc32 compensation attack</match>
    <info type="cve">2001-0144</info>
    <info type="link">http://www.securityfocus.com/bid/2347/info/</info>
    <description>sshd: SSH CRC-32 Compensation attack</description>
    <mitre>
      <id>T1210</id>
    </mitre>
    <group>exploit_attempt,gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,nist_800_53_SI.2,pci_dss_11.4,pci_dss_6.2,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5715" level="3">
    <if_sid>5700</if_sid>
    <match>^Accepted|authenticated.$</match>
    <description>sshd: authentication success.</description>
    <mitre>
      <id>T1078</id>
      <id>T1021</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5716" level="5">
    <if_sid>5700</if_sid>
    <match>^Failed|^error: PAM: Authentication</match>
    <description>sshd: authentication failed.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5717" level="4">
    <if_sid>5700</if_sid>
    <match>error: Bad prime description in line</match>
    <description>sshd: configuration error (moduli).</description>
  </rule>

  <rule id="5718" level="5">
    <if_sid>5700</if_sid>
    <match>not allowed because</match>
    <description>sshd: Attempt to login using a denied user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5719" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5718</if_matched_sid>
    <description>sshd: Multiple access attempts using a denied user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5720" level="10" frequency="8">
    <if_matched_sid>5716</if_matched_sid>
    <same_source_ip />
    <description>sshd: Multiple authentication failures.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5721" level="0">
    <if_sid>5700</if_sid>
    <match>Received disconnect from</match>
    <description>sshd: System disconnected from sshd.</description>
  </rule>

  <rule id="5722" level="0">
    <if_sid>5700</if_sid>
    <match>Connection closed</match>
    <description>sshd: ssh connection closed.</description>
    <group>gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5723" level="0">
    <if_sid>5700</if_sid>
    <match>error: buffer_get_bignum2_ret: negative numbers not supported</match>
    <info>This maybe a bad key in authorized_keys.</info>
    <description>sshd: key error.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.a.2.IV,hipaa_164.312.e.1,hipaa_164.312.e.2.I,hipaa_164.312.e.2.II,hipaa_164.312.b,nist_800_53_SC.8,nist_800_53_AU.6,pci_dss_4.1,pci_dss_10.6.1,tsc_CC6.7,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5724" level="0">
    <if_sid>5700</if_sid>
    <match>fatal: buffer_get_bignum2: buffer error</match>
    <info>This error may relate to ssh key handling.</info>
    <description>sshd: key error.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.a.2.IV,hipaa_164.312.e.1,hipaa_164.312.e.2.I,hipaa_164.312.e.2.II,hipaa_164.312.b,nist_800_53_SC.8,nist_800_53_AU.6,pci_dss_4.1,pci_dss_10.6.1,tsc_CC6.7,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5725" level="0">
    <if_sid>5700</if_sid>
    <match>fatal: Write failed: Host is down</match>
    <description>sshd: Host ungracefully disconnected.</description>
  </rule>

  <rule id="5726" level="5">
    <if_sid>5700</if_sid>
    <match>error: PAM: Module is unknown for</match>
    <description>sshd: Unknown PAM module, PAM misconfiguration.</description>
  </rule>

  <rule id="5727" level="0">
    <if_sid>5700</if_sid>
    <match>failed: Address already in use.</match>
    <description>sshd: Attempt to start sshd when something already bound to the port.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_CM.1,pci_dss_10.6.1,pci_dss_2.2.3,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5728" level="4">
    <if_sid>5700</if_sid>
    <match>Authentication service cannot retrieve user credentials</match>
    <info>May be related to PAM module errors.</info>
    <description>sshd: Authentication services were not able to retrieve user credentials.</description>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5729" level="0">
    <if_sid>5700</if_sid>
    <match>debug1: attempt</match>
    <description>sshd: Debug message.</description>
  </rule>

  <rule id="5730" level="4">
    <if_sid>5700</if_sid>
    <regex>error: connect to \S+ port \d+ failed: Connection refused</regex>
    <description>sshd: SSHD is not accepting connections.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.b,nist_800_53_AU.6,pci_dss_10.6.1,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5731" level="6">
    <if_sid>5700</if_sid>
    <match>AKASSH_Version_Mapper1.</match>
    <description>sshd: SSH Scanning.</description>
    <mitre>
      <id>T1046</id>
    </mitre>
    <group>gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,pci_dss_11.4,recon,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5732" level="0">
    <if_sid>5700</if_sid>
    <match>error: connect_to </match>
    <description>sshd: Possible port forwarding failure.</description>
  </rule>

  <rule id="5733" level="0">
    <if_sid>5700</if_sid>
    <match>Invalid credentials</match>
    <description>sshd: User entered incorrect password.</description>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5734" level="0">
    <if_sid>5700</if_sid>
    <match>Could not load host key</match>
    <description>sshd: sshd could not load one or more host keys.</description>
    <info>This may be related to an upgrade to OpenSSH.</info>
  </rule>

  <rule id="5735" level="0">
    <if_sid>5700</if_sid>
    <match>Write failed: Broken pipe</match>
    <description>sshd: Failed write due to one host disappearing.</description>
  </rule>

  <rule id="5736" level="0">
    <if_sid>5700</if_sid>
    <match>^error: setsockopt SO_KEEPALIVE: Connection reset by peer$|</match>
    <match>^error: accept: Software caused connection abort$</match>
    <description>sshd: Connection reset or aborted.</description>
  </rule>

  <rule id="5737" level="5">
    <if_sid>5700</if_sid>
    <match>^fatal: Cannot bind any address.$</match>
    <description>sshd: cannot bind to configured address.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.b,nist_800_53_AU.6,pci_dss_10.6.1,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5738" level="5">
    <if_sid>5700</if_sid>
    <match>set_loginuid failed opening loginuid$</match>
    <description>sshd: pam_loginuid could not open loginuid.</description>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5739" level="4">
    <if_sid>5700</if_sid>
    <match>^error: Could not stat AuthorizedKeysCommand</match>
    <description>sshd: configuration error (AuthorizedKeysCommand)</description>
  </rule>

  <rule id="5740" level="4">
    <if_sid>5700</if_sid>
    <match>Connection reset by peer$</match>
    <description>sshd: connection reset by peer</description>
  </rule>

  <rule id="5741" level="4">
    <if_sid>5700</if_sid>
    <match>Connection refused$</match>
    <description>sshd: connection refused</description>
  </rule>

  <rule id="5742" level="4">
    <if_sid>5700</if_sid>
    <match>Connection timed out$</match>
    <description>sshd: connection timed out</description>
    <group>gdpr_IV_35.7.d,hipaa_164.312.a.1,nist_800_53_AC.2,pci_dss_8.1.5,tsc_CC6.1,</group>
  </rule>

  <rule id="5743" level="4">
    <if_sid>5700</if_sid>
    <match>No route to host$</match>
    <description>sshd: no route to host</description>
  </rule>

  <rule id="5744" level="4">
    <if_sid>5700</if_sid>
    <match>failure direct-tcpip$</match>
    <description>sshd: port forwarding issue</description>
  </rule>

  <rule id="5745" level="4">
    <if_sid>5700</if_sid>
    <match>Transport endpoint is not connected$</match>
    <description>sshd: transport endpoint is not connected</description>
  </rule>

  <rule id="5746" level="4">
    <if_sid>5700</if_sid>
    <match>get_remote_port failed$</match>
    <description>sshd: get_remote_port failed</description>
  </rule>

  <!-- http://www.gossamer-threads.com/lists/openssh/users/47438 -->
  <rule id="5747" level="6">
    <if_sid>5700</if_sid>
    <match>bad client public DH value</match>
    <description>sshd: bad client public DH value</description>
  </rule>

  <rule id="5748" level="6">
    <if_sid>5700</if_sid>
    <match>Corrupted MAC on input.</match>
    <description>sshd: corrupted MAC on input</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.b,nist_800_53_AU.6,pci_dss_10.6.1,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5749" level="4">
    <if_sid>5700</if_sid>
    <match>^Bad packet length</match>
    <description>sshd: bad packet length</description>
  </rule>

  <rule id="5750" level="0">
    <decoded_as>sshd</decoded_as>
    <if_sid>5700</if_sid>
    <match>Unable to negotiate with |Unable to negotiate a key|fatal: no matching</match>
    <description>sshd: could not negotiate with client.</description>
  </rule>

  <rule id="5751" level="1">
    <decoded_as>sshd</decoded_as>
    <if_sid>5700</if_sid>
    <match>no hostkey alg [preauth]</match>
    <description>sshd: No hostkey alg.</description>
  </rule>

  <rule id="5752" level="2">
    <if_sid>5750</if_sid>
    <match>no matching key exchange method found.|Unable to negotiate a key exchange method</match>
    <description>sshd: Client did not offer an acceptable key exchange method.</description>
  </rule>

  <rule id="5753" level="2">
    <if_sid>5750</if_sid>
    <match>no matching cipher found</match>
    <description>sshd: could not negotiate with client, no matching cipher.</description>
  </rule>

  <rule id="5754" level="1">
    <if_sid>5700</if_sid>
    <match>Failed to create session: </match>
    <description>sshd: failed to create a session.</description>
  </rule>

  <rule id="5755" level="3">
    <if_sid>5700</if_sid>
    <match>bad ownership or modes for file</match>
    <description>sshd: Authentication refused due to owner/permissions of authorized_keys.</description>
    <group>authentication_failed,gpg13_7.1,</group>
  </rule>

  <rule id="5756" level="0">
    <if_sid>5700</if_sid>
    <match> failed, subsystem not found$</match>
    <description>sshd: subsystem request failed.</description>
  </rule>

  <rule id="5757" level="0">
    <if_sid>5700</if_sid>
    <match>but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!$</match>
    <description>Bad DNS mapping.</description>
  </rule>

  <rule id="5758" level="8">
    <if_sid>5700,5710</if_sid>
    <match>^error: maximum authentication attempts exceeded </match>
    <description>Maximum authentication attempts exceeded.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gpg13_7.1,</group>
  </rule>

  <rule id="5759" level="2">
    <if_sid>5750</if_sid>
    <match>no matching mac found</match>
    <description>sshd: could not negotiate with client, no matching mac.</description>
  </rule>

  <rule id="5760" level="5">
    <if_sid>5700,5716</if_sid>
    <match>Failed password|Failed keyboard|authentication error</match>
    <description>sshd: authentication failed.</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5761" level="0">
    <if_sid>5700</if_sid>
    <match>Disconnected from user</match>
    <description>sshd: ssh connection closed.</description>
    <group>gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5762" level="4">
    <if_sid>5700</if_sid>
    <match>Connection reset</match>
    <description>sshd: connection reset</description>
  </rule>

  <rule id="5763" level="10" frequency="8" timeframe="120" ignore="60">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip/>
    <description>sshd: brute force trying to get access to the system. Authentication failed.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
{{- end }}