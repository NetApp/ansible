Installs the SolidFire Enterprise SDS
=====================================

This role automates the deployment and configuration of the SolidFire eSDS solution.
Verison 1.1

Requirements
------------

This role requires the target systems use RHEL 7.6+ Additionally, the SolidFire eSDS RPM should either be published 
to an http file server addressable by the inventory, or added to the files/ directory of the role.

Role Variables
--------------

For details about recommended values for the `*_iface` and `*_devices` variables, see the product documentation and/or 
the sf_sds_config.yaml file man page (`man 5 sf_sds_config`)

NOTE: The Minimum Specification checks are documented in a separate [README](tasks/min-specification/README.md) file, 
including more information about specific variables that can be configured for this capability.

| Variable                        | Required | Description                | Comments                                      |
|---------------------------------|----------|----------------------------|-----------------------------------------------|
| solidfire_element_rpm           | yes*     | URL or local path for RPM  | See the example below [1]                     |
| na_sf_filename                  | no       | basename of above variable | Do not change                                 |
| mgmt_iface                      | yes      | Valid NIC iface name       | Redundant NIC (team/bond)                     |
| storage_iface                   | yes      | Valid NIC iface name       | Redundant NIC (team/bond)                     |
| storage_devices                 | yes      | List of storage devices    | /dev/sdb                                      |
|                                 |          |                            | /dev/disk/by-uuid/nvme-ZZZZZZZ-YYYY_XXXXXXXX  |
|                                 |          |                            | /dev/disk/by-id/nvme-ZZZZZZZ-YYYY_XXXXXXXX    |
| cache_devices                   | yes      | List of cache devices      | /dev/disk/by-id/nvme-ZZZZZZZ-YYYY_XXXXXXXX    |
| na_sf_validate_certs            | no       | Check SSL/TLS certs        | Can be overridden for RPM sources w/o certs   |
| na_sf_use_proxy                 | no       | Use proxy conf             | Uses proxy ENV vars on target host            |
| na_sf_sds_service_state         | no       | State of solidfire service | Value is "started" by default                 |
| na_sf_deactivate_checks         | no       | Deactivate Min Spec checks | Not defined by default, Set to "True" to      |
|                                 |          |                            | deactivate the minimum specification checks   |
| na_sf_allow_derivatives         | no       | Install on RHEL derivatives| Do we allow installation more than RHEL?      |
|                                 |          |                            | As of now, that means CentOS                  |
| na_sf_language                  | no       | Default: en-us             | See tasks/min-specification/README.md         |
| sf_ignore_teamdctl_abrt_cores   | No       | True                       | Ignore teamdctl cores in ABRT                 |

[1] = `http://<server><:port>/<path>/solidfire-element-W.X.Y.Z-N.el{7,8}.x86_64.rpm`

Example Playbook
----------------
```
 - name: Install SolidFire Enterprise SDS 
   hosts: all
   gather_facts: True

   roles:
     - role: nar_solidfire_sds_install
       vars:
         solidfire_element_rpm: http://<server>/<path>/solidfire-element-W.X.Y.Z-N.el{7,8}.x86_64.rpm
         mgmt_iface: mgmt_t0
         storage_iface: strg_t1
         storage_devices:
           - /dev/disk/by-id/<id for sda>
           - /dev/disk/by-id/<id for sdb>
           - /dev/disk/by-id/<id for sdd>
           - /dev/disk/by-id/<id for sde>
           - /dev/disk/by-id/<id for sdf>
           - /dev/disk/by-id/<id for sdg>
           - /dev/disk/by-id/<id for sdh>
           - /dev/disk/by-id/<id for sdi>
           - /dev/disk/by-id/<id for sdj>
         cache_devices:
           - /dev/disk/by-id/<id for sdc>
```

    
License
-------

GNU v3

Author Information
------------------
NetApp
https://www.netapp.com
