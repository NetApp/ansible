nar_santricity_host
=========

    Configures storage pools, volumes, hosts, host groups, and port interfaces for NetApp E-Series storage arrays
    using iSCSI, FC, or SAS protocols.

Requirements
------------
    - Ansible 2.5 or later
    - NetApp E-Series E2800 platform or newer or NetApp E-Series SANtricity Web Services Proxy configured for older E-Series Storage arrays.

Instructions
------------
    1) Use the ansible-galaxy command line tool to install nar_santricity_host role on your Ansible management host.

          ansible-galaxy install schmots1.nar_santricity_host

    2) Add your NetApp E-Series storage systems(s) to the Ansible inventory. Copy and modify the example storage array inventory file below or see the example
       inventory files found in this roles examples directory. For the full list variables pertaining to this role, review the role variables section below.

    3) Lastly, add the role to your execution playbook. See the example playbook section below.

Example Playbook
----------------
    - hosts: eseries_storage_systems
      connection: local               # NetApp E-Series modules utilize SANtricity Web Services REST API and should be executed on the control node (i.e. local)
      gather_facts: false             # Fact gathering should be disabled to avoid gathering unecessary facts about the control node.
      tasks:
      - name: Ensure NetApp E-Series storage systeem is properly configured
        include_role:
          name: schmots1.nar_santricity_host
         
Example Storage System Inventory File
-------------------------------------
    # file: host_vars/192.168.1.100
    ansible_connection: local                   # All E-Series modules interact with NetApp SANtricity Web Services REST API. This will force the Ansible
                                                #    commands to be run locally on the control node.

    # NetApp E-Series storage system identifier and credentials
    eseries_api_url: https://192.168.1.7:8443/devmgr/v2/    # WebService's URL
    eseries_api_username: admin                             # Storage system username and password
    eseries_api_password: mypass
    eseries_validate_certs: no                              # Forces SSL certificate certification
    
    eseries_initiator_protocol: iscsi           # Choices: iscsi, fc, sas

    # Controller port definitions
    eseries_controller_port_config_method: static
    eseries_controller_port_subnet_mask: 255.255.255.0
    eseries_controller_port:
      controller_a:
        ports:
          - channel: 1
            address: 192.168.2.100
      controller_b:
        ports:
          - channel: 1
            address: 192.168.3.100
    
    # Storage pool and volume configuration
    eseries_storage_pool_configuration:
      - name: pool[1-2]                         # Name or name scheme for the storage group
        volumes:                                # Storage group's volume list
          - name: "[pool]_volume[A-C]"          # Name or naming scheme for the volume. *Note, quotes are only needed when brackets start the string.
            host: servers                       # Host or host group to where the volume will be mapped. Inventory will
                                                # will be searched for target name.
            size: 100                           # Size of volume (default units: gb)

Role Variables
--------------
    # For complete variable list and definitions, see defaults/main.yml file.

    # Default storage array credentials for interacting with web services api
    -------------------------------------------------------------------------
    eseries_ssid:            # Storage array identifier. This value will be 1 when enteracting with the embedded web services, otherwise the identifier will be
                                  defined on the web services proxy.
    eseries_api_url:         # Url for the web services api. Example: https://192.168.10.100/devmgr/v2
    eseries_api_username:    # Username for the web services api.
    eseries_api_password:    # Password for the web services api.
    eseries_validate_certs:  # Whether the SSL certificates should be verified. (boolean)
    
    eseries_initiator_protocol:   # Specifies the initiator protocol type. Choices: iscsi (default), fc, sas

    # NetApp E-Series controller port definitions
    ---------------------------------------------
    eseries_controller_port_config_method:  # General port configuration method definition for both controllers. Choices: static, dhcp
    eseries_controller_port_gateway:        # General port IPv4 gateway for both controllers.
    eseries_controller_port_subnet_mask:    # General port IPv4 subnet mask for both controllers.
    eseries_controller_port_mtu:            # General port maximum transfer units (MTU) for both controllers. Any value greater than 1500 (specified in bytes).
    eseries_controller_port:
      controller_a:                         # Controller A port definitions
        ports:
          - channel:                        # (required) Channel of the port to modify. This will be a numerical value that represents the port; typically read
                                                left to right on the HIC.
            state:                          # Whether the port should be enabled.
            config_method:                  # Port configuration method; address, gateway, and subnet_mask must be specified when config_method=static unless
                                                specified at a higher level in the inventory (common_port_definitions or eseries_controller_port_*).
                                                Choices: static, dhcp
            address:                        # Port IPv4 address
            gateway:                        # Port IPv4 gateway
            subnet_mask:                    # Port IPv4 subnet_mask
       controller_b:                        # Controller B port definitions. Any option defined for controller_a can be defined here.

    # Target discovery specifications
    ---------------------------------
    eseries_target_name:                # iSCSI target name that will be seen by the initiator
    eseries_target_chap_secret:         # iSCSI chap secret
      *** Note: add the following to ansible-playbook command to update the chap secret: --extra-vars "eseries_target_chap_secret_update=True

    # Manual host definitions
    -------------------------
    eseries_host_object:
      - name:                 # Host label as referenced by the storage array.
        host_type:            # Windows (non-clustering)-1, Windows (clustering)-6, Vmware-10, Linux-28
        group:                # Host's host group
        ports:                # List of port definitions
          - type:             # Port protocol definition (iscsi, fc, sas, ib, nvme)
            label:            # Arbitrary port label
            port:             # Port initiator (iqn, wwn, etc)

    # Storage pool configuration definitions and configuration parameters
    ---------------------------------------------------------------------
    Name schemes: Storage pool and volume names can be used to specify a naming scheme to produce a list of storage pools and volumes. The scheme are defined by
                  brackets and can be used to specify a range of lowercase letters, uppercase letters, range of single digit numbers, any top-level inventory
                  variables, and the current defined storage pool (volume only).

    eseries_storage_pool_configuration:
      - name:                         # Name or name scheme (see above) for the storage pool.
        state:                        # Specifies whether the storage pool should exist (present, absent). When removing an existing storage array all of the
                                          volumes must be defined with state=absent.
        common_volume_configuration:  # Any option that can be specified at the volume level can be generalized here at the storage pool level. This is useful
                                          when all volumes share common configuration definitions.
        volumes:                      # List of volumes associated the storage pool.
          - state:                    # Specifies whether the volume should exist (present, absent)
            name:                     # (required) Name or name scheme (see above) for the volume(s) to be created in the storage pool(s)
            target:                   # Host or host group to where the volume will be mapped.
            size:                     # Size of the volume or presented size of the thinly provisioned volume.
            size_unit:                # Unit size for the size, thin_volume_repo_size, and thin_volume_max_repo_size 
                                          Choices: bytes, b, kb, mb, gb, tb, pb, eb, zb, yb
            workload_name:            # Name of the volume's workload. This can be defined using the metadata option or, if already defined, specify one 
                                          already created on the storage array.
            metadata:                 # Dictionary containing arbitrary entries normally used for defining the volume(s) workload.

License
-------
    BSD

Author Information
------------------
    Nathan Swartz (@ndswartz)
