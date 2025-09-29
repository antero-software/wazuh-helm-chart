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
opensearch_security.auth.anonymous_auth_enabled: false
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
{{- define "wazuh.local_rules" }}
<group name="aws,amazon,cloudwatch,">
  <rule id="100010" level="3">
    <decoded_as>json</decoded_as>
    <field name="httpSourceName">CF</field>
    <description>Cloudwatch Logs</description>
  </rule>


  <rule id="100018" level="0">
    <if_sid>100010</if_sid>
    <id>^2|^3</id>
    <compiled_rule>is_simple_http_request</compiled_rule>
    <description>Ignored URLs (simple queries).</description>
  </rule>

  <rule id="100011" level="5">
    <if_sid>100010</if_sid>
    <id>^4</id>
    <description>Web server 400 error code.</description>
    <group>attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100012" level="0">
    <if_sid>100011</if_sid>
    <field name="httpRequest.args">.jpg$|.gif$|favicon.ico$|.png$|robots.txt$|.css$|.js$|.jpeg$</field>
    <compiled_rule>is_simple_http_request</compiled_rule>
    <description>Ignored extensions on 400 error codes.</description>
  </rule>

  <rule id="100013" level="7">
    <if_sid>100010,100018</if_sid>
    <field name="httpRequest.args">=select%20|select+|insert%20|%20from%20|%20where%20|union%20|union+|where+|null,null|xp_cmdshell</field>
    <description>SQL injection attempt.</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>attack,sql_injection,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100014" level="6">
    <if_sid>100010</if_sid>

    <!-- Attempt to do directory transversal, simple sql injections,
      -  or access to the etc or bin directory (unix). -->
    <field name="httpRequest.args">cmd.exe|root.exe|_mem_bin|msadc|/winnt/|/boot.ini|</field>
    <description>Common web attack.</description>
    <mitre>
      <id>T1055</id>
      <id>T1083</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100015" level="6">
    <if_sid>100010</if_sid>
    <!--
    <url>%3Cscript|%3C%2Fscript|script>|script%3E|SRC=javascript|IMG%20|</url>
    <url>%20ONLOAD=|INPUT%20|iframe%20</url>
    -->
    <field name="httpRequest.args">%3Cscript|%3C%2Fscript|script>|script%3E|SRC=javascript|IMG%20|</field>
    <!-- <field name="httpRequest.args">%3Cscript|%3C%2Fscript|script>|script%3E|SRC=javascript|IMG%20|%20ONLOAD=|INPUT%20|iframe%20</field>>
    <field name="httpRequest.args">%20ONLOAD=|INPUT%20|iframe%20</field>	    
	    -->
    <description>XSS (Cross Site Scripting) attempt.</description>
    <mitre>
      <id>T1059.007</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.7,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100016" level="6">
    <if_sid>100013, 100014, 100015</if_sid>
    <id>^200</id>
    <description>A web attack returned code 200 (success).</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100110" level="6">
    <if_sid>100010</if_sid>
    <field name="httpRequest.args">?-d|?-s|?-a|?-b|?-w</field>
    <description>PHP CGI-bin vulnerability attempt.</description>
    <mitre>
      <id>T1210</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100019" level="6">
    <if_sid>100010</if_sid>
    <field name="httpRequest.args">+as+varchar</field>
    <regex>%2Bchar\(\d+\)%2Bchar\(\d+\)%2Bchar\(\d+\)%2Bchar\(\d+\)%2Bchar\(\d+\)%2Bchar\(\d+\)</regex>
    <description>MSSQL Injection attempt (/ur.php, urchin.js)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <!-- If your site have a search engine, you may need to ignore
    - it in here.
    -->
  <rule id="100017" level="0">
    <if_sid>100013, 100014, 100015</if_sid>
    <field name="httpRequest.uri">^/search.php?search=|^/index.php?searchword=</field>
    <description>Ignored URLs for the web attacks</description>
  </rule>

  <rule id="100115" level="13" maxsize="7900">
    <if_sid>100010</if_sid>
    <description>URL too long. Higher than allowed on most </description>
    <description>browsers. Possible attack.</description>
    <mitre>
      <id>T1499</id>
    </mitre>
    <group>invalid_access,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.8,pci_dss_10.2.4,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SA.11,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <!-- 500 error codes, server error
    - http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
    -->
  <rule id="100020" level="5">
    <if_sid>100010</if_sid>
    <id>^50</id>
    <description>Web server 500 error code (server error).</description>
  </rule>

  <rule id="100021" level="4">
    <if_sid>100020</if_sid>
    <id>^501</id>
    <description>Web server 501 error code (Not Implemented).</description>
  </rule>

  <rule id="100022" level="5">
    <if_sid>100020</if_sid>
    <id>^500</id>
    <description>Web server 500 error code (Internal Error).</description>
    <group>system_error,</group>
  </rule>

  <rule id="100023" level="4">
    <if_sid>100020</if_sid>
    <id>^503</id>
    <description>Web server 503 error code (Service unavailable).</description>
  </rule>


  <!-- Rules to ignore crawlers -->
  <rule id="100040" level="0">
    <if_sid>100011</if_sid>
    <compiled_rule>is_valid_crawler</compiled_rule>
    <description>Ignoring google/msn/yahoo bots.</description>
  </rule>

  <!-- Ignoring nginx 499's -->
  <rule id="100041" level="0">
    <if_sid>100011</if_sid>
    <id>^499</id>
    <description>Ignored 499's on nginx.</description>
  </rule>


  <rule id="100051" level="10" frequency="14" timeframe="90">
    <if_matched_sid>100011</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 400 error codes </description>
    <description>from same source ip.</description>
    <mitre>
      <id>T1595.002</id>
    </mitre>
    <group>web_scan,recon,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100052" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100013</if_matched_sid>
    <same_source_ip />
    <description>Multiple SQL injection attempts from same </description>
    <description>source ip.</description>
    <mitre>
      <id>T1055</id>
    </mitre>
    <group>attack,sql_injection,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100053" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100014</if_matched_sid>
    <same_source_ip />
    <description>Multiple common web attacks from same source ip.</description>
    <mitre>
      <id>T1055</id>
      <id>T1083</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100054" level="10" frequency="10" timeframe="120">
    <if_matched_sid>100015</if_matched_sid>
    <same_source_ip />
    <description>Multiple XSS (Cross Site Scripting) attempts </description>
    <description>from same source ip.</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.7,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100061" level="10" frequency="14" timeframe="120">
    <if_matched_sid>100021</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 501 error code (Not Implemented).</description>
    <mitre>
      <id>T1595.002</id>
    </mitre>
    <group>web_scan,recon,pci_dss_6.5,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100062" level="10" frequency="14" timeframe="120">
    <if_matched_sid>100022</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 500 error code (Internal Error).</description>
    <group>system_error,pci_dss_6.5,pci_dss_10.6.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SA.11,nist_800_53_AU.6,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100063" level="10" frequency="14" timeframe="120">
    <if_matched_sid>100023</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 503 error code (Service unavailable).</description>
    <mitre>
      <id>T1498</id>
    </mitre>
    <group>web_scan,recon,pci_dss_6.5,pci_dss_11.4,pci_dss_10.6.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_SA.11,nist_800_53_SI.4,nist_800_53_AU.6,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100064" level="6">
    <if_sid>100010</if_sid>
    <field name="httpRequest.args">=%27|select%2B|insert%2B|%2Bfrom%2B|%2Bwhere%2B|%2Bunion%2B</field>
    <description>SQL injection attempt.</description>
    <mitre>
      <id>T1055</id>
      <id>T1190</id>
    </mitre>
    <group>attack,sqlinjection,attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100065" level="6">
    <if_sid>100010</if_sid>
    <field name="httpRequest.args">%EF%BC%87|%EF%BC%87|%EF%BC%87|%2531|%u0053%u0045</field>
    <description>SQL injection attempt.</description>
    <mitre>
      <id>T1055</id>
      <id>T1190</id>
    </mitre>
    <group>attack,sqlinjection,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

<!--
    Shellshock detected
    Pattern: "(){:;};" (with spaces)
    Decoder: web-accesslog_decoders.xml

    Examples:
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 404 292 "-" "() { :;};/usr/bin/perl ..."
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { :;};/usr/bin/perl ..."
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { foo:; };/usr/bin/perl ..."
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { ignored; };/usr/bin/perl ..."
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { gry; };/usr/bin/perl ..."

    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { _; } >_[$($())] { /usr/bin/perl ... }"
    192.168.2.100 - - [02/Nov/2015:01:35:55 +0100] "GET /cgi-bin/test.sh HTTP/1.1" 200 292 "-" "() { _; foo; } >_[$($())] { /usr/bin/perl ... }"
    -->

  <!--
    Shellshock attempt
    Code: 4xx, 5xx
  -->
  <rule id="100066" level="6">
    <if_sid>100011, 100020</if_sid>
    <regex>"\(\)\s*{\s*\w*:;\s*}\s*;|"\(\)\s*{\s*\w*;\s*}\s*;</regex>
    <description>Shellshock attack attempt</description>
    <mitre>
      <id>T1068</id>
      <id>T1190</id>
    </mitre>
    <info type="cve">CVE-2014-6271</info>
    <info type="link">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271</info>
    <group>attack,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100067" level="6">
    <if_sid>100011, 100020</if_sid>
    <regex>"\(\)\s*{\s*_;\.*}\s*>_[\$\(\$\(\)\)]\s*{</regex>
    <description>Shellshock attack attempt</description>
    <mitre>
      <id>T1068</id>
      <id>T1190</id>
    </mitre>
    <info type="cve">CVE-2014-6278</info>
    <info type="link">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278</info>
    <group>attack,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <!--
    Shellshock detected
    Code: 2xx, 3xx
  -->
  <rule id="100068" level="15">
    <if_sid>100018</if_sid>
    <regex>"\(\)\s*{\s*\w*:;\s*}\s*;|"\(\)\s*{\s*\w*;\s*}\s*;</regex>
    <description>Shellshock attack detected</description>
    <mitre>
      <id>T1068</id>
      <id>T1190</id>
    </mitre>
    <info type="cve">CVE-2014-6271</info>
    <info type="link">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271</info>
    <group>attack,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100069" level="15">
    <if_sid>100018</if_sid>
    <regex>"\(\)\s*{\s*_;\.*}\s*>_[\$\(\$\(\)\)]\s*{</regex>
    <description>Shellshock attack detected</description>
    <mitre>
      <id>T1068</id>
      <id>T1190</id>
    </mitre>
    <info type="cve">CVE-2014-6278</info>
    <info type="link">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278</info>
    <group>attack,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100070" level="6">
    <if_sid>100010</if_sid>
    <field name="httpRequest.args">%2csleep|sysdate()|nslookup%20dns.sqli</field>
    <description>SQL injection attempt.</description>
    <group>attack,sqlinjection,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100071" level="6">
   <if_sid>100010</if_sid>
   <field name="httpRequest.args">select%20|insert%20</field>
   <description>SQL injection attempt.</description>
   <group>attack,sqlinjection,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,</group>
  </rule>
</group>
{{- end }}
{{- define "wazuh.local_decoders" }}
<decoder name="json">
	<parent>json</parent>
	<regex>httpSourceName":"(\.*)",</regex>
	<order>aws.source</order>
</decoder>

<decoder name="json">
        <parent>json</parent>
	<regex>webaclId":"\.*/\.*/(\.*)/</regex>
        <order>wafruleset</order>
</decoder>

<decoder name="json">
	<parent>json</parent>
	<plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
{{- end }}