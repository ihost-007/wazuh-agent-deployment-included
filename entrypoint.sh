#!/bin/bash
###################
# wazuh-agent + juice-shop
###################
set -euo pipefail

echo "Starting Wazuh Agent setup..."

# -------- ENV (override via manifest) --------
WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh.wazuh.svc.cluster.local}"          # enrollment server

# Ensure wazuh group/user exist
if ! getent group wazuh >/dev/null; then
  echo "Creating group 'wazuh'..."
  groupadd -r wazuh
fi
if ! id -u wazuh >/dev/null 2>&1; then
  echo "Creating user 'wazuh'..."
  useradd -r -g wazuh -d /var/ossec -s /bin/false wazuh
fi

# Ownership for /var/ossec (preserve any mounted read-only files)
if [ -d /var/ossec ]; then
  find /var/ossec -exec chown wazuh:wazuh {} + || true
fi

# Make sure wazuh-control is executable if already present
if [ -f /var/ossec/bin/wazuh-control ]; then
  chmod +x /var/ossec/bin/wazuh-control || true
fi

# Install Wazuh Agent 4.13.0 if missing
if [ ! -x /var/ossec/bin/wazuh-control ]; then
  echo "Wazuh agent not found. Installing 4.13.0..."
  apt-get update
  # Assumes Wazuh APT repo already configured in the image
  apt-get install -y wazuh-agent=4.13.0
fi

# Build ossec.conf (no password enrollment)
HOSTNAME_SHORT="$(hostname -s || hostname || echo agent)"
cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>

    <config-profile>ubuntu, ubuntu24, ubuntu24.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>

    <!-- Enrollment without password; manager must allow it (or pre-provide client.keys) -->
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${WAZUH_MANAGER}</manager_address>
      <port>1515</port>
      <agent_name>${HOSTNAME_SHORT}</agent_name>
      <!-- No authorization_pass_path -->
    </enrollment>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>900</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>no</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>no</disabled>
    <timeout>1800</timeout>
    <interval>10m</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>10m</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>10m</interval>
    <skip_nfs>no</skip_nfs>
  </sca>

  <syscheck>
    <disabled>no</disabled>
    <frequency>900</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
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
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>no</skip_nfs>
    <skip_dev>no</skip_dev>
    <skip_proc>no</skip_proc>
    <skip_sys>no</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
    <directories check_all="yes" whodata="yes" realtime="yes">/Users</directories>
    <directories check_all="yes" whodata="yes" realtime="yes">/home</directories>
  </syscheck>

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

  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>
</ossec_config>
EOF

# Start Wazuh agent (no registration password envs)
echo "Starting Wazuh Agent..."
/var/ossec/bin/wazuh-control start

# Show agent logs
tail -f /var/ossec/logs/ossec.log &

######################################
# juice-shop application
######################################
if [ -f "/application/package.json" ]; then
  cd /application
  npm start
else
  mkdir -p /application
  cd /
  wget -q https://github.com/juice-shop/juice-shop/releases/download/v17.1.1/juice-shop-17.1.1_node20_linux_x64.tgz
  tar -xzvf juice-shop-17.1.1_node20_linux_x64.tgz -C /application/ --strip-components=1
  cd /application
  npm install --omit=dev --ignore-scripts
  npm start
fi
