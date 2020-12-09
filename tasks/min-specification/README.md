Minimum Specification Checks
============================

As with most of the tasks defined for this install role, the tasks for the Minimum 
Specification checker can be executed in isolation from the actual installation.

Minimum Specification Checker Variables
---------------------------------------

These variables can be used to configure specific behavior from the Minimum Specification Checker.

| Variable                          | Required | Description                | Comments                                        |
|-----------------------------------|----------|----------------------------|-------------------------------------------------|
| na_sf_deactivate_checks           | no       | Deactivate all checks      | Not defined by default, Set to "True" to        |
|                                   |          |                            | deactivate the minimum specification checks     |
| na_sf_allow_derivatives           | no       | Install on RHEL derivatives| Whether to allow installation more than RHEL,   |
|                                   |          |                            | i.e. CentOS as well                             |
| na_sf_extra_checks_path           | no       | Path to directory w/checks | Path to directory w/checks (rel. to `tasks/`)   |
| na_sf_extra_checks                | no       | List of additional checks  | A list of check prefixes, i.e. 'platform' for   |
|                                   |          |                            | platform-check.yml                              |
| na_sf_language                    | no       | Language spec for messages | Currently supports 'en-us' only                 |

Adding more checks
-----------------------------

The Minimum Specification Checker will let you add custom checks for it to run/execute.

Look at the existing structure of the task lists in `tasks/min-specification` to see examples
of how checks are implemented.

In order to add checks, name the individual check task list files performing the checks using a <name>-checks.yml 
pattern. 

`<name>` is the name of the check (I.e. `platform` -> `plaform-checks.yml`). 

Note: Use the plural form for the `-checks.yml` section of the file name! 

The checks can be stored somewhere other than in the `nar_solidfire_sds_install` role directory structure by
setting the `na_sf_extra_checks_path` variable to a path relative from `nar_solidfire_sds_install/tasks`

Copy the file(s) containing the additional checks into either the directory specified in the 
`na_sf_extra_checks_path` _or_ to the `tasks/min-specification` folder/directory of the 
`nar_solidfire_sds_install` rol. 

Add the new check - in the example, use `platform` - to the  list of checks by adding 
something similar to the following example to your own playbook:

```ansible
# Note that this path is relative to the `tasks/` directory 
# of the `nar_solidfire_sds_install` role
#
# In this example, the `custom-checks` directory needs to be located
# in a directory above the directory where `nar_solidfire_sds_install` is
# located on the controller
#
- name: Ensure we know where to add extra checks from
  set_fact:
    na_sf_extra_checks_path: ../../../custom-checks/
- name: Ensure we added a platform check
  set_fact:
    na_sf_extra_checks: "{{ na_sf_extra_checks + ['platform'] }}"
```

Required files for additional (custom) checks:
    * <name>-checks.yml
    * extra-messages-*.yml (where `*` == any valid language spec, i.e. 'en-us', 'en-gb', 'nb_no', etc)
    * report.yml

Internationalization (I18N) of messages
---------------------------------------

By default, the role ships with English (US) error messages. 

This can be overridden by setting the `na_sf_language` variable to another 
valid I18N definition in your playbook/inventory, and create a custom 
`extra-messages-*.yml` file. This file must be located in the directory 
pointed to by the `na_sf_extra_spec_checks` variable.

Messages are handled as a `variable: text` pairing in the `*-messages-*.yml` files.

Additional (default) message files can be added to the `tasks/min-specification` directory 
as Yaml files using the `min-specification-messages-en_gb.yml` or 
`min-specification-messages-nb_no.yml` pattern for the file name. (I.e. The designation 
for the language as the terminating text before the `.yml` extension.)  

Using the Minimum Specification Checker without installing an RPM
=================================================================

Example playbook to *only* execute the minimum specification checker:

```ansible
- name: Test the minmum specification checker
  hosts: all
  gather_facts: True
  
  tasks:
    - name: Ensure we run only the minimum specification checker
      block:
        - set_fact:
            na_sf_deactivate_checks: False
            na_sf_default_check_path: <path_to_nar_solidifire_sds_install>/tasks/min-specification
            na_sf_language: 'en-us'

        - include_role:
            name: nar_solidfire_sds_install
            tasks_from: min-specification/min-specification-checks.yml
```
