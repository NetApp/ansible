na_ontap_vserver_create
=========

Create one or more Vservers.

Creates Vserver with specified protocol(s).  Will join to Windows Domain provided AD credintals are included.
Modifies default rule for NFS protocol to 0.0.0.0/0 ro to allow NFS connections

Requirements
------------

Since this uses the NetApp ONTAP modules it will require the python library netapp-lib as well as the Ansible 2.8 release.

Role Variables
--------------
```
cluster: <short ONTAP name of cluster>
hostname: <ONTAP mgmt ip or fqdn>
username: <ONTAP admin account>
password: <ONTAP admin account password>

#Based on if Variables != or == None determins if a section runs.  Each variable will take one or more dictonary entries.  Simply omit sections
#that you don't want to run.  The following would run all sections

vservers: # Vservers to create
  - { name: nfs_vserver, aggr: aggr1, protocol: nfs }
  - { name: cifs_vserver, aggr: aggr1, protocol: cifs }

vserver_dns: # DNS at the Vserver level.
  - { vserver: cifs_vserver, dns_domains: lab.local, dns_nameservers: 172.32.0.40 }

lifs: # interfaces for the Vservers being created
  - { name: nfs_vserver_data_lif, vserver: nfs_vserver, node: cluster-01, port: e0c, protocol: nfs, address: 172.32.0.193, netmask: 255.255.255.0 }
  - { name: cifs_vserver_data_lif, vserver: nfs_vserver, node: cluster-01, port: e0c, protocol: nfs, address: 172.32.0.194, netmask: 255.255.255.0 }

cifs: # Vservers to join to an AD Domain
  - { vserver: cifs_vserver, cifs_server_name: netapp1, domain: ansible.local, force: true }

fcp: # sets FCP ports as Target
  - { adapter: 0e, node: cluster-01 }
```
Dependencies
------------

The tasks in this role are dependent on information from the na_ontap_gather_facts module.
The task for na_ontap_gather_facts can not be excluded.

Example Playbook
----------------
```
---
- hosts: localhost
  vars_prompt:
    - name: admin_user_name
      prompt: domain admin (enter if skipped)
    - name: admin_password
      prompt: domain admin password (enter if skipped)
  vars_files:
    - globals.yml
  vars:
    input: &input
      hostname: "{{ netapp_hostname }}"
      username: "{{ netapp_username }}"
      password: "{{ netapp_password }}"
  tasks:
  - name: Get Ontapi version
    na_ontap_gather_facts:
      state: info
      <<: *input
      https: true
      ontapi: 32
      validate_certs: false
  - import_role:
      name: na_ontap_vserver_create
    vars:
      <<: *input
```
I use a globals file to hold my variables.
```
---
globals.yml
cluster_name: cluster

netapp_hostname: 172.32.0.182
netapp_username: admin
netapp_password: netapp123

vservers:
  - { name: nfs_vserver, aggr: aggr1, protocol: NFS }
  - { name: cifs_vserver, aggr: aggr1, protocol: cifs }
  - { name: nas_vserver, aggr: aggr1, protocol: 'cifs,nfs' }

lifs:
  - { name: nfs_vserver_data_lif, vserver: nfs_vserver, node: vsim-01, port: e0c, protocol: nfs, address: 172.32.0.183, netmask: 255.255.255.0 }
  - { name: cifs_vserver_data_lif, vserver: cifs_vserver, node: vsim-01, port: e0c, protocol: nfs, address: 172.32.0.184, netmask: 255.255.255.0 }
  - { name: nas_vserver_data_lif, vserver: nas_vserver, node: vsim-02, port: e0c, protocol: nfs, address: 172.32.0.185, netmask: 255.255.255.0 }

vserver_dns:
  - { vserver: cifs_vserver, dns_domains: lab.local, dns_nameservers: 172.32.0.40 }

cifs:
  - { vserver: cifs_vserver, cifs_server_name: netapp1, domain: openstack.local, force: true }
```
---
- hosts: localhost
  vars_prompt:
    - name: admin_user_name
      prompt: domain admin (enter if skipped)
    - name: admin_password
      prompt: domain admin password (enter if skipped)
  vars_files:
    - globals.yml
  vars:
    input: &input
      hostname: "{{ netapp_hostname }}"
      username: "{{ netapp_username }}"
      password: "{{ netapp_password }}"
  tasks:
  - name: Get Ontapi version
    na_ontap_gather_facts:
      state: info
      <<: *input
      https: true
      ontapi: 32
      validate_certs: false
  - import_role:
      name: na_ontap_vserver_create
    vars:
      <<: *input

License
-------

GNU v3

Author Information
------------------
NetApp
http://www.netapp.io
