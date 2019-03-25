na_ontap_cluster_config
=========

Configure one or more of the following ONTAP settings:

Licenses
Disk Assignments
Cluster DNS
NTP
SNMP
MOTD
Aggregates
Ports
Interface Groups
VLANS
Broadcast Domains
Intercluster LIFs

Requirements
------------

Since this uses the NetApp ONTAP modules it will require the python library netapp-lib as well as the Ansible 2.8 release.

Role Variables
--------------
cluster: <short ONTAP name of cluster>
hostname: <ONTAP mgmt ip or fqdn>
username: <ONTAP admin account>
password: <ONTAP admin account password>

Based on if Variables != or == None determins if a section runs.  Each variable will take one or more dictonary entries.  Simply omit sections
that you don't want to run.  The following would run all sections

license_codes: AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAA,AAAAAAAAAAAAAA

disks: # at current the disks module assigns all visiable disks to a node.  If you are wanting to split disks, currently that has to be done manually
  - cluster-01
  - cluster-02

motd: "The login in message you would like displayed when someone ssh's into the system"

dns:
  - { dns_domains: ansible.local, dns_nameservers: 1.1.1.1 }

ntp:
  - { server_name: time.nist.gov, version: auto }

snmp:
  - { community_name: public, access_control: ro }

aggrs:
  - { name: aggr1, node: cluster-01, disk_count: 26, max_raid: 26 }
  - { name: aggr2, node: cluster-02, disk_count: 26, max_raid: 26 }

ports:   #* Ports also has variables 'autonegotiate', and 'flowcontrol' which default to true, and none but can be overriden by your playbook
  - { node: cluster-01, port: e0c, mtu: 9000 }

ifgrps:
  - { name: a0a, node: cluster-01, port: "e0a", mode: multimode }
  - { name: a0a, node: cluster-02, port: "e0a", mode: multimode }
  - { name: a0a, node: cluster-01, port: "e0b", mode: multimode }
  - { name: a0a, node: cluster-02, port: "e0b", mode: multimode }

vlans:
  - { id: 201, node: cluster-01, parent: a0a }

bcasts:
  - { name: Backup, mtu: 9000, ipspace: default, ports: 'cluster-01:e0c,vsim-02:e0c' }

inters:
  - { name: intercluster_1, address: 172.32.0.187, netmask: 255.255.255.0, node: cluster-01, port: e0c }
  - { name: intercluster_2, address: 172.32.0.188, netmask: 255.255.255.0, node: cluster-02, port: e0c }

Dependencies
------------

The tasks in this role are dependent on information from the na_ontap_gather_facts module.
The task for na_ontap_gather_facts can not be excluded.

Example Playbook
----------------

I use a globals file to hold my variables.

globals.yml
cluster_name: cluster

netapp_hostname: 172.32.0.182
netapp_username: admin
netapp_password: netapp123

license_codes: <removed>

aggrs:
  - { name: aggr1, node: cluster-01, disk_count: 26, max_raid: 26 }
  - { name: aggr2, node: cluster-02, disk_count: 26, max_raid: 26 }

ifgrps:
  - { name: a0a, node: cluster-01, port: "e0a", mode: multimode }
  - { name: a0a, node: cluster-02, port: "e0a", mode: multimode }
  - { name: a0a, node: cluster-01, port: "e0b", mode: multimode }
  - { name: a0a, node: cluster-02, port: "e0b", mode: multimode }

inters:
  - { name: intercluster_1, address: 172.32.0.187, netmask: 255.255.255.0, node: cluster-01, port: e0c }
  - { name: intercluster_2, address: 172.32.0.188, netmask: 255.255.255.0, node: cluster-02, port: e0c }

I then use a simple playbook to call my globals and the role.

cluster_config.yml
---
- hosts: localhost
  vars_files:
    - globals.yml
  vars:
    input: &input
      hostname: "{{ netapp_hostname }}"
      username: "{{ netapp_username }}"
      password: "{{ netapp_password }}"
  tasks:
  - import_role:
      name: na_ontap_cluster_config
    vars:
      <<: *input

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
