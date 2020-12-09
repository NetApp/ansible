nar_solidfire_sds_compliance
=========

This role automates validating NetApp compliance for SolidFire eSDS.

Requirements
------------

This role requires the target systems use RHEL 7.6

Role Variables
--------------

| Variable                        | Required | Description                         | Comments                                              |
|---------------------------------|----------|-------------------------------------|-------------------------------------------------------|
| sf_compliance_report_dir        | no       | Directory to log reports            | Defaults to directory ansible was run from            |
|                                 |          |                                     | in a "solidfire_sds_compliance_reports" sub directory |
| sf_compliance_report_path       | no       | Full path to compliance report file | solidfire_sds_report_                                 |
| sf_print_report                 | no       | Print report to ansible runtime     | true (defalt), false will not print                   |

Example Playbook
----------------

```
  - hosts: all
    roles:
      - role: nar_solidfire_sds_compliance
```
License
-------

GPL-3.0-only

Author Information
------------------

NetApp
https://www.netapp.com
