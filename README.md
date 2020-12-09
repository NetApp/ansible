Role Name
=========
nar_solidfire_sds_upgrade


Description
-----------
This role is designed to perform an update of the NetApp SolidFire Enterprise SDS software package and then safely perform a rolling upgrade of the cluster member nodes. 


Requirements
------------
1. This role requires that NetApp/Solidfire eSDS be running on the target systems.
2. It also requires the `nar_solidfire_sds_install` role, which is available on GitHub (https://github.com/netapp/ansible).


Role Variables
--------------

| Variable                            | Required | Default       | Description                                                                                                                    |
|-------------------------------------|----------|---------------|--------------------------------------------------------------------------------------------------------------------------------|
| solidfire_element_rpm               | Yes      | N/A           | URL or path to the SolidFire eSDS RPM. For example https://<hostname>/<path>/solidfire-element-<version>.<platform>.<arch>.rpm |
| sf_mgmt_virt_ip                     | Yes      | N/A           | Virtual IP address (MVIP) for the management interface                                                                         |
| sf_cluster_admin_passwd             | Yes      | N/A           | The password for the Cluster Administrator user (Recommend using ansible vault)                                                |
| sf_cluster_admin_username           | Yes      | sfadmin       | The username for the Cluster Administrator user                                                                                |
| sf_cluster_connect_timeout          | No       | 20            | The API connection timeout value in seconds                                                                                    |
| sf_wait_delay                       | No       | 60            | Time to wait in seconds before polling to see if node has entered/exited Maintenance Mode                                      |
| sf_api_version                      | No       | 12.2          | The version of the SolidFire eSDS API to use (default is 12.2 and should not be modified!)                                     |
| yes_i_want_to_ignore_cluster_faults | No       | False         | Do not change. If set to True, will allow the upgrade to proceed even if a cluster fault is present                            |
| i_want_to_break_idempotency         | No       | False         | If set to True, causes the role to exit if the specified RPM represents something other than an upgrade for the node           |
| sf_maint_mode_duration:             | No       | "01:00:00"    | Duration the node will stay in maintenance mode before it automatically exits. Uses "HH:MM:SS" format                          |
| sf_use_proxy                        | No       | True          | Whether to use proxy settings on the target host (or not). Default is "yes" or "true"                                          |
|                                     |          |               | Note: Setting a negative value currently has no effect due to a bug in Ansible version 2.9.x or older. Instead, better to use  |
|                                     |          |               |       the environment variable "no_proxy" in a playbook as a workaround when needed until the bug is fixed by Ansible.         |
|                                     |          |               | environment:                                                                                                                   |
|                                     |          |               |   no_proxy: <target_ip_address>                                                                                                |
| sf_validate_certs                   | No       | True          | Do we validate SSL/TLS certificates and fail if invalid?                                                                       |
| sf_pip_extra_args                   | No       | ""            | Specify extra Python pip installer arguments when installing the required controller libraries/modules                         |
| sf_allow_cluster_subset_upgrade     | No       | False         | Whether to fail the play if there are more nodes in the cluster than what the inventory includes (Default is to fail).         |
|                                     |          |               | When set to True, users can chose to specify in the inventory a subset of the cluster nodes to be upgraded. However, the       |
|                                     |          |               | cluster version will not be updated until all nodes have been upgraded.                                                        |


Dependencies
------------
The `nar_solidfire_sds_install` role, available on GitHub (https://github.com/netapp/ansible) provides a few of the tasks used by this `nar_solidfire_sds_upgrade` role.


An Example Playbook
-------------------
Playbook file name: `update-SFeSDS.yml`

```
- name: Rolling Upgrade of SolidFire Enterprise SDS
  hosts: hpe-dl360-g10
  gather_facts: True

  roles:
     - role: nar_solidfire_sds_upgrade
```

License
-------
MIT

Author Information
------------------
NetApp
https://www.netapp.com
