# Role Name
`na_ots_deploy`: Create, configure and run the OTS deploy VM.

# Requirements
The Server that will host the deploy VM should be prepared according to ONTAP Select specifications withing the appropriate virtualization environment and storage and networking configured as required.
Ansible 2.7 or greater is needed to run this role.

# Role Variables
```yaml
target_vcenter_or_esxi_host: <Name or IP address of the target vCenter or esxi host>
host_login: <login for the vcenter or esxi host given above>
ovf_path: <path to the OVF file to install the deploy VM>
datacenter_name: <Name of the datacenter in the vCenter if applicable>
esx_cluster_name: <Name of the ESX cluster in the vCenter if applicable>
datastore_name: <Name of the datastore where the deploy VM will reside>
mgt_network: <Management network to be used for deploy VM IP address>
deploy_name: <Name of the deploy VM>
deploy_ipAddress: <IP address for the deploy VM>
deploy_gateway: <Gateway for the deploy VM IP>
deploy_proxy_url: <Proxy URL for Deploy VM>
deploy_netMask: <Netmask>
deploy_primaryDNS: <Primary DNS IP address for the Deploy VM>
deploy_secondaryDNS: <Optional secondary DNS IP address>
deploy_searchDomains: <Search Domain>
```
# Example Playbook
```yaml
---
- name: Create ONTAP Select Deploy VM from OVA (ESXi)
  hosts: "{{ target_vcenter_or_esxi_host }}" # Entry in Ansible 'hosts' file
  gather_facts: false
  connection: 'local'
  vars_files:
  - vars_deploy.yml # All Variables
  - vars_deploy_pwd.yml # host_password & deploy_password
  roles:
    - na_ots_deploy
```
# Example Global file
Using a global file for variables helps. Sample below:
```yaml
target_vcenter_or_esxi_host: "10.xxx.xx.xx"
host_login: "yourlogin@yourlab.local"
ovf_path: "/run/deploy/ovapath/ONTAPdeploy.ova"
datacenter_name: "your-Lab"
esx_cluster_name: "your Cluster"
datastore_name: "your-select-dt"
mgt_network: "your-mgmt-network"
deploy_name: "test-deploy-vm"
deploy_ipAddress: "10.xxx.xx.xx"
deploy_gateway: "10.xxx.xx.1"
deploy_proxy_url: ""
deploy_netMask: "255.255.255.0"
deploy_product_company: "NetApp"
deploy_primaryDNS: "10.xxx.xx.xx"
deploy_secondaryDNS: ""
deploy_searchDomains: "your.search.domain.com"
```
# License
BSD
# Author Information
NetApp
