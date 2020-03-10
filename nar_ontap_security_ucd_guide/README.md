nar_ontap_security_ucd_guide
=========

Configures and hardens the ONTAP cluster to the specifications detailed in the NetApp DoD Unified Capabilities (UC) Deployment Guide (NetApp TR-4754).
Use extreme caution when utilizing this role.  If used incorrectly it's possible to lock yourself ouf of the ONTAP system where you are unable to gain access.
Reviewing TR-4754 prior to deploying this is highly recommended.

Requirements
------------

-Since this uses the NetApp ONTAP modules it will require the python library netapp-lib as well as the Ansible 2.8 or later release.
-NetApp ONTAP 9.6 or later.
-The cluster will be deployed with the built-in default cluster admin account, but once complete the final procedure disables the admin account, and no further access through that account is possible.

Role Variables
--------------
```
A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

hostname: <cluster management IP of the cluster>
username: admin
password: <cluster admin account password>
node01_name: <node 1 of the HA pair node name>
node02_name: <node 2 of the HA pair node name>
admin_vserver: <the admin server name>

fw_dns_allow_ip: 0.0.0.0/0
# The allowed dns IP’s can be changed, but the recommendation is to keep 0.0.0.0/0

fw_ssh_allow_ip: 0.0.0.0/0
# The allowed ssh IP’s can be changed, but the recommendation is to keep 0.0.0.0/0

fw_ntp_allow_ip: 0.0.0.0/0
# The allowed ntp IP’s can be changed, but the recommendation is to keep 0.0.0.0/0

core_mgmt_allow_ip: 0.0.0.0/0
# The allowed IP's for LIF Services core_mgmt can be changed, but the recommendation is to keep 0.0.0.0/0

data_core_cifs_allow_ip: 0.0.0.0/0
# Necessary for the domain access vserver to join the domain, the allowed IP's for LIF Services data_core_cifs can be changed, but the recommendation is to keep 0.0.0.0/0

node01_mgmt_lif_name: <node 1 mgmt lif name>
node02_mgmt_lif_name: <node 2 mgmt lif name>

domain_access_vserver: <domain access vserver name>
# The name of the vserver used for domain accounts that will administer the cluster with domain access rights

da_root_vol_name: <domain access vserver root vol>
# The name of the root_volume for the domain access vserver

da_root_vol_aggr_name: <domain access vserver aggr name>
# The name of the data aggregate that will contain the domain access vserver svm root volume

node01_da_failover_target_port: <domain access vserver node 1 lif failover port>
node02_da_failover_target_port: <domain access vserver node 2 lif failover port>
node01_da_lif_home_port: <domain access vserver lif home port>
lif_da_ip: <domain access vserver lif IP>
lif_da_mask: <domain access vserver lif mask>

da_dns_domain_name: <domain access vserver dns name>
# Typically in Active Directory environments this is the AD DNS servers FQDN

da_dns_ip: <domain access vserver DNS IP address>

da_cifs_server_name: <cifs server name>
# This is the windows AD machine account name for the CIFS server

da_ad_domain_user_name: <domain username>
# A windows account with permissions to join a computer to the domain

da_ad_domain_passwd: <domain password>

da_ad_ou_name:  <AD Organization Unit Name>

ad_da_user_name: <AD SVM admin act name>
# This will be an Active Directory user account name with permissions to login and manage the SVM

ntp_server_ip: <ntp server ip address>
syslog_server: <syslog server IP address>

emergency_user_name: emergency_acct
# This account name can be changed if desired.  The account is only used during network outages and only has access through the serial console.

emergency_user_password: <the emergency user password>

allowed_http_ip: 127.0.0.1/32
# The allowed http IP’s can be changed, but the recommendation is to keep only the local host.

allowed_https_ip: 127.0.0.1/32
# The allowed https IP’s can be changed, but the recommendation is to keep only the local host.
```

Dependencies
------------

The tasks in this role are dependent on information from the na_ontap_gather_facts module. The task for na_ontap_gather_facts can not be excluded

Example Playbook
----------------
```
# In this example the variable file used is called ucd_guide_vars.yml

- hosts: localhost
  name: Security Harden
  vars_files:
   - ucd_guide_vars.yml
  vars:
   login: &login
     hostname: "{{ hostname }}"
     username: "{{ username }}"
     password: "{{ password }}" 
  tasks:
  - name: Enable IPv6
    na_ontap_command:
      command: ['network options ipv6 modify -enabled true']
      https: true
      validate_certs: false
      <<: *login
  - name: Disable autosupport
    na_ontap_autosupport:
      state: absent
      node_name: "{{ node01_name }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Modify Service Processor Network ipv6
    na_ontap_service_processor_network:
      state: present
      address_type: ipv6
      is_enabled: false
      dhcp: none
      node: "{{ node01_name }}"
      ip_address: 0::0
      prefix_length: 64
      https: true
      validate_certs: false
      #<<: *login  
  - name: Modify Service Processor Network ipv4
    na_ontap_service_processor_network:
      state: present
      address_type: ipv4
      is_enabled: false
      dhcp: none
      node: "{{ node01_name }}"
      ip_address: 0.0.0.0
      netmask: 255.255.255.0
      gateway_ip_address: 0.0.0.0
      <<: *login
  - name: Set SSH Ciphers and Algorithims
    na_ontap_command:
      command: ['security ssh modify -vserver "{{ admin_vserver }}" -key-exchange-algorithms diffie-hellman-group-exchange-sha256 -ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes128-gcm,aes256-gcm']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy HTTP Deny
    na_ontap_firewall_policy:
      vserver: "{{ admin_vserver }}"
      state: present
      node: "{{ node01_name }}"
      enable: enable
      service: http
      allow_list: "127.0.0.1/32,::1/128"
      logging: enable
      policy: secure_mgmt
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy DNS Allow CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service dns -allow-list "{{ fw_dns_allow_ip }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt LIF Services HTTPS Deny CLI
    na_ontap_command:
      command: ['network interface service-policy create -policy secure_mgmt -allowed-addresses 127.0.0.1/32, ::1/128 -vserver "{{ admin_vserver }}" -services management-https']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt LIF Services SSH Allow CLI
    na_ontap_command:
      command: ['network interface service-policy add-service -vserver "{{ admin_vserver }}" -policy secure_mgmt -services management-ssh -allowed-addresses "{{ fw_ssh_allow_ip }}"']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt LIF Services core-management Allow CLI
    na_ontap_command:
      command: ['network interface service-policy add-service -vserver "{{ admin_vserver }}" -policy secure_mgmt -services management-core -allowed-addresses "{{ core_mgmt_allow_ip }}"']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy NDMP Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service ndmp -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy RSH Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service rsh -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy SNMP Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service snmp -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy TELNET Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service telnet -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: Mgmt Firewall Policy NTP Allow CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ admin_vserver }}" -policy secure_mgmt -service ntp -allow-list "{{ fw_ntp_allow_ip  }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Assign Secure Mgmt LIF Services Policy to Node 01 Managment CLI
    na_ontap_command:
      command: ['net interface modify -vserver "{{ admin_vserver }}" -lif "{{ node01_mgmt_lif_name }}" -service-policy secure_mgmt']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Assign Mgmt FW Policy to Node 01 Management
    na_ontap_interface:
      state: present
      interface_name: "{{ node01_mgmt_lif_name  }}"
      firewall_policy: secure_mgmt
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Create Domain Access SVM
    na_ontap_svm:
      state: present
      name: "{{ domain_access_vserver  }}"
      root_volume: "{{ da_root_vol_name }}"
      root_volume_aggregate: "{{ da_root_vol_aggr_name }}"
      root_volume_security_style: mixed
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy HTTP Deny
    na_ontap_firewall_policy:
      vserver: "{{ domain_access_vserver }}"
      enable: enable
      node: "{{ node01_name }}"
      service: http
      allow_list: "127.0.0.1/32,::1/128"
      logging: enable
      policy: domain_access
      https: true
      validate_certs: false
      state: present
      <<: *login
  - name: AD_DA Firewall Policy DNS Allow CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service dns -allow-list "{{ fw_dns_allow_ip }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA LIF Services HTTPS Deny CLI
    na_ontap_command:
      command: ['network interface service-policy create -policy domain_access -allowed-addresses 127.0.0.1/32, ::1/128 -vserver "{{ domain_access_vserver }}" -services management-https']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy NDMP Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service ndmp -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy RSH Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service rsh -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy SNMP Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service snmp -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy TELNET Deny CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service telnet -allow-list 127.0.0.1/32, ::1/128']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA Firewall Policy NTP Allow CLI
    na_ontap_command:
      command: ['firewall policy create -vserver "{{ domain_access_vserver }}" -policy domain_access -service ntp -allow-list "{{ fw_ntp_allow_ip  }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA LIF Services SSH Deny CLI
    na_ontap_command:
      command: ['network interface service-policy add-service -vserver "{{ domain_access_vserver }}" -policy domain_access -service management-ssh -allowed-addresses 127.0.0.1/32, ::1/128']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA LIF Services data-cifs Allow CLI
    na_ontap_command:
      command: ['network interface service-policy add-service -vserver "{{ domain_access_vserver }}" -policy domain_access -service data_core -allowed-addresses "{{ data_core_cifs_allow_ip }}"']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Create AD_DA LIF Failover Group Node01 Target CLI
    na_ontap_command:
      command: ['network interface failover-groups create -vserver "{{ domain_access_vserver }}" -failover-group da_fail_grp1 -targets "{{ node01_da_failover_target_port }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Create AD_DA LIF Failover Group Node02 Target CLI
    na_ontap_command:
      command: ['network interface failover-groups create -vserver "{{ domain_access_vserver }}" -failover-group da_fail_grp1 -targets "{{ node02_da_failover_target_port }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Create AD_DA LIF
    na_ontap_interface:
      state: present
      interface_name: lif_domain_access
      role: data
      protocols: cifs
      home_node: "{{ node01_name }}"
      home_port: "{{ node01_da_lif_home_port }}"
      address: "{{ lif_da_ip }}"
      netmask: "{{ lif_da_mask }}"
      admin_status: up
      firewall_policy: domain_access
      is_auto_revert: true
      vserver: "{{ domain_access_vserver }}"
      https: true
      validate_certs: false
      <<: *login
  - name: AD_DA LIF Services data-cifs Allow CLI
    na_ontap_command:
      command: ['network interface service-policy add-service -vserver "{{ domain_access_vserver }}" -policy domain_access -service data_core -allowed-addresses "{{ data_core_cifs_allow_ip }}"']
      privilege: advanced
      https: true
      validate_certs: false
      <<: *login
  - name: Add AD_DA LIF to Failover Group da_fail_grp1 CLI
    na_ontap_command:
      command: ['network interface modify -vserver "{{ domain_access_vserver }}" -lif lif_domain_access -failover-group da_fail_grp1']
      https: true
      validate_certs: false
      <<: *login
  - name: Add AD_DA DNS Name Server IP address
    na_ontap_dns:
      state: present
      vserver: "{{ domain_access_vserver }}"
      domains: "{{ da_dns_domain_name }}"
      nameservers: "{{ da_dns_ip }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Join AD_DA SVM to CIFS Domain
    na_ontap_cifs_server:
      state: present
      cifs_server_name: "{{ da_cifs_server_name  }}"
      vserver: "{{ domain_access_vserver }}"
      admin_password: "{{ da_ad_domain_passwd }}"
      admin_user_name: "{{ da_ad_domain_user_name }}"
      domain: "{{ da_dns_domain_name }}"
      service_state: started
      ou: "{{ da_ad_ou_name }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Enable Domain Tunnel Login for DA SVM CLI
    na_ontap_command:
      command: ['security login domain-tunnel create -vserver "{{ domain_access_vserver }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Create NTP server
    na_ontap_ntp:
      state: present
      version: auto
      server_name: "{{ ntp_server_ip }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Modify SSH timeouts CLI
    na_ontap_command:
      command: ['system timeout modify -timeout 10']
      https: true
      validate_certs: false
      <<: *login
  - name: Add Syslog Server CLI
    na_ontap_command:
      command: ['event destination modify -name allevents -syslog "{{ syslog_server }}"']
      https: true
      validate_certs: false
      <<: *login
  - name: Send all EMS events to Syslog Server CLI
    na_ontap_command:
      command: ['event route add-destinations -messagename * -destinations allevents']
      https: true
      validate_certs: false
      <<: *login
  - name: Create admin_ssh default
    na_ontap_user_role:
      state: present
      name: admin_ssh
      command_directory_name: DEFAULT
      access_level: all
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Create admin_ssh SP deny
    na_ontap_user_role:
      state: present
      name: admin_ssh
      command_directory_name: system node service-processor
      access_level: none
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false
     <<: *login
  - name: Modify Admin SSH role CLI
    na_ontap_command:
      command: ['security login role config modify -role admin_ssh -vserver "{{ admin_vserver }}" -username-alphanum disabled -passwd-minlength 14 -passwd-alphanum enabled -passwd-min-special-chars 1 -passwd-expirty-time 60 -require-initial-passwd-update enabled -max-failed-login-attempts 3 -lockout-duration 60 -disallwed-reuse 24 -change-delay 1 -username-minlength 4']
      https: true
      validate_certs: false
      <<: *login
  - name: Create Emergency User for Console access
    na_ontap_user:
      state: present
      name: "{{ emergency_user_name }}"
      application: console
      authentication_method: password
      set_password: "{{ emergency_user_password }}"
      lock_user: True
      role_name: admin
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Add Emergency User for SP access
    na_ontap_user:
      state: present
      name: "{{ emergency_user_name }}"
      application: service-processor
      authentication_method: password
      set_password: "{{ emergency_user_password }}"
      lock_user: True
      role_name: admin
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false
      <<: *login
  - name: Create AD DA User
    na_ontap_user:
      state: present
      name: "{{ ad_da_user_name }}"
      application: ssh
      authentication_method: domain
      set_password: "{{ emergency_user_password }}"
      lock_user: True
      role_name: admin_ssh
      vserver: "{{ admin_vserver }}"
      https: true
      validate_certs: false      
      <<: *login
  - name: Disable Web Access
    na_ontap_command:
      command: ['security login lock -vserver "{{ admin_vserver }}" -username admin']
      https: true
      validate_certs: false
      <<: *login
```

License
-------

GNU v3

Author Information
------------------

NetApp http://www.netapp.io

