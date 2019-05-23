#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {"metadata_version": "1.1",
                    "status": ["preview"],
                    "supported_by": "community"}


DOCUMENTATION = """
---
module: netapp_e_hostgroup
version_added: "2.2"
short_description: NetApp E-Series manage array host groups
author:
    - Kevin Hulquest (@hulquest)
    - Nathan Swartz (@ndswartz)
description: Create, update or destroy host groups on a NetApp E-Series storage array.
extends_documentation_fragment:
    - netapp.eseries
options:
    state:
        required: true
        description:
            - Whether the specified host group should exist or not.
        choices: ["present", "absent"]
    name:
        required: false
        description:
            - Name of the host group to manage
            - This option is mutually exclusive with I(id).
    new_name:
        required: false
        description:
            - Specify this when you need to update the name of a host group
    id:
        required: false
        description:
            - Host reference identifier for the host group to manage.
            - This option is mutually exclusive with I(name).
    hosts:
        required: false
        description:
            - List of host names/labels to add to the group
"""
EXAMPLES = """
    - name: Configure Hostgroup
      netapp_e_hostgroup:
        ssid: "{{ ssid }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        validate_certs: "{{ netapp_api_validate_certs }}"
        state: present
"""
RETURN = """
clusterRef:
    description: The unique identification value for this object. Other objects may use this reference value to refer to the cluster.
    returned: always except when state is absent
    type: str
    sample: "3233343536373839303132333100000000000000"
confirmLUNMappingCreation:
    description: If true, indicates that creation of LUN-to-volume mappings should require careful confirmation from the end-user, since such a mapping
                 will alter the volume access rights of other clusters, in addition to this one.
    returned: always
    type: bool
    sample: false
hosts:
    description: A list of the hosts that are part of the host group after all operations.
    returned: always except when state is absent
    type: list
    sample: ["HostA","HostB"]
id:
    description: The id number of the hostgroup
    returned: always except when state is absent
    type: str
    sample: "3233343536373839303132333100000000000000"
isSAControlled:
    description: If true, indicates that I/O accesses from this cluster are subject to the storage array's default LUN-to-volume mappings. If false,
                 indicates that I/O accesses from the cluster are subject to cluster-specific LUN-to-volume mappings.
    returned: always except when state is absent
    type: bool
    sample: false
label:
    description: The user-assigned, descriptive label string for the cluster.
    returned: always
    type: str
    sample: "MyHostGroup"
name:
    description: same as label
    returned: always except when state is absent
    type: str
    sample: "MyHostGroup"
protectionInformationCapableAccessMethod:
    description: This field is true if the host has a PI capable access method.
    returned: always except when state is absent
    type: bool
    sample: true
"""

import json

from pprint import pformat
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.urls import open_url
from ansible.module_utils.api import basic_auth_argument_spec
from ansible.module_utils._text import to_native

try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'

try:
    from urlparse import urlparse, urlunparse
except ImportError:
    from urllib.parse import urlparse, urlunparse


def eseries_host_argument_spec():
    """Retrieve a base argument specification common to all NetApp E-Series modules"""
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        api_username=dict(type='str', required=True),
        api_password=dict(type='str', required=True, no_log=True),
        api_url=dict(type='str', required=True),
        ssid=dict(type='str', required=False, default='1'),
        validate_certs=dict(type='bool', required=False, default=True)
    ))
    return argument_spec


class NetAppESeriesModule(object):
    """Base class for all NetApp E-Series modules.

    Provides a set of common methods for NetApp E-Series modules, including version checking, mode (proxy, embedded)
    verification, http requests, secure http redirection for embedded web services, and logging setup.

    Be sure to add the following lines in the module's documentation section:
    extends_documentation_fragment:
        - netapp.eseries

    :param dict(dict) ansible_options: dictionary of ansible option definitions
    :param str web_services_version: minimally required web services rest api version (default value: "02.00.0000.0000")
    :param bool supports_check_mode: whether the module will support the check_mode capabilities (default=False)
    :param list(list) mutually_exclusive: list containing list(s) of mutually exclusive options (optional)
    :param list(list) required_if: list containing list(s) containing the option, the option value, and then
    a list of required options. (optional)
    :param list(list) required_one_of: list containing list(s) of options for which at least one is required. (optional)
    :param list(list) required_together: list containing list(s) of options that are required together. (optional)
    :param bool log_requests: controls whether to log each request (default: True)
    """
    DEFAULT_TIMEOUT = 60
    DEFAULT_SECURE_PORT = "8443"
    DEFAULT_REST_API_PATH = "devmgr/v2/"
    DEFAULT_REST_API_ABOUT_PATH = "devmgr/utils/about"
    DEFAULT_HEADERS = {"Content-Type": "application/json", "Accept": "application/json",
                       "netapp-client-type": "Ansible-%s" % ansible_version}
    HTTP_AGENT = "Ansible / %s" % ansible_version
    SIZE_UNIT_MAP = dict(bytes=1, b=1, kb=1024, mb=1024 ** 2, gb=1024 ** 3, tb=1024 ** 4,
                         pb=1024 ** 5, eb=1024 ** 6, zb=1024 ** 7, yb=1024 ** 8)

    def __init__(self, ansible_options, web_services_version=None, supports_check_mode=False,
                 mutually_exclusive=None, required_if=None, required_one_of=None, required_together=None,
                 log_requests=True):
        argument_spec = eseries_host_argument_spec()
        argument_spec.update(ansible_options)

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=supports_check_mode,
                                    mutually_exclusive=mutually_exclusive, required_if=required_if,
                                    required_one_of=required_one_of, required_together=required_together)

        args = self.module.params
        self.web_services_version = web_services_version if web_services_version else "02.00.0000.0000"
        self.ssid = args["ssid"]
        self.url = args["api_url"]
        self.log_requests = log_requests
        self.creds = dict(url_username=args["api_username"],
                          url_password=args["api_password"],
                          validate_certs=args["validate_certs"])

        if not self.url.endswith("/"):
            self.url += "/"

        self.is_embedded_mode = None
        self.web_services_validate = None

    def _is_web_services_valid(self):
        """Verify proxy or embedded web services meets minimum version required for module.

        The minimum required web services version is evaluated against version supplied through the web services rest
        api. AnsibleFailJson exception will be raised when the minimum is not met or exceeded.

        This helper function will update the supplied api url if secure http is not used for embedded web services

        :raise AnsibleFailJson: raised when the contacted api service does not meet the minimum required version.
        """
        if not self.web_services_validate:

            url_parts = list(urlparse(self.url))
            if not url_parts[0] or not url_parts[1]:
                self.module.fail_json(msg="Failed to provide valid API URL. Example: https://192.168.1.100:8443/devmgr/v2. URL [%s]." % self.url)

            if url_parts[0] not in ["http", "https"]:
                self.module.fail_json(msg="Protocol must be http or https. URL [%s]." % self.url)

            self.url = "%s://%s/" % (url_parts[0], url_parts[1])
            about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
            rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, ignore_errors=True, **self.creds)

            if rc != 200:
                self.module.warn("Failed to retrieve web services about information! Retrying with secure ports. Array Id [%s]." % self.ssid)
                self.url = "https://%s:8443/" % url_parts[1].split(":")[0]
                about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
                try:
                    rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, **self.creds)
                except Exception as error:
                    self.module.fail_json(msg="Failed to retrieve the webservices about information! Array Id [%s]. Error [%s]."
                                              % (self.ssid, to_native(error)))

            major, minor, other, revision = data["version"].split(".")
            minimum_major, minimum_minor, other, minimum_revision = self.web_services_version.split(".")

            if not (major > minimum_major or
                    (major == minimum_major and minor > minimum_minor) or
                    (major == minimum_major and minor == minimum_minor and revision >= minimum_revision)):
                self.module.fail_json(msg="Web services version does not meet minimum version required. Current version: [%s]."
                                          " Version required: [%s]." % (data["version"], self.web_services_version))

            self.module.log("Web services rest api version met the minimum required version.")
            self.web_services_validate = True

            if self.is_embedded():
                self.url = "https://%s:8443/" % url_parts[1].split(":")[0]

        return self.web_services_validate

    def is_embedded(self):
        """Determine whether web services server is the embedded web services.

        If web services about endpoint fails based on an URLError then the request will be attempted again using
        secure http.

        :raise AnsibleFailJson: raised when web services about endpoint failed to be contacted.
        :return bool: whether contacted web services is running from storage array (embedded) or from a proxy.
        """
        if self.is_embedded_mode is None:
            about_url = self.url + self.DEFAULT_REST_API_ABOUT_PATH
            try:
                rc, data = request(about_url, timeout=self.DEFAULT_TIMEOUT, headers=self.DEFAULT_HEADERS, **self.creds)
                self.is_embedded_mode = not data["runningAsProxy"]
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve the webservices about information2! Array Id [%s]. Error [%s]."
                                          % (self.ssid, to_native(error)))

        return self.is_embedded_mode

    def request(self, path, data=None, method='GET', headers=None, ignore_errors=False):
        """Issue an HTTP request to a url, retrieving an optional JSON response.

        :param str path: web services rest api endpoint path (Example: storage-systems/1/graph). Note that when the
        full url path is specified then that will be used without supplying the protocol, hostname, port and rest path.
        :param data: data required for the request (data may be json or any python structured data)
        :param str method: request method such as GET, POST, DELETE.
        :param dict headers: dictionary containing request headers.
        :param bool ignore_errors: forces the request to ignore any raised exceptions.
        """
        if self._is_web_services_valid():
            if headers is None:
                headers = self.DEFAULT_HEADERS

            if not isinstance(data, str) and headers["Content-Type"] == "application/json":
                data = json.dumps(data)

            if path.startswith("/"):
                path = path[1:]
            request_url = self.url + self.DEFAULT_REST_API_PATH + path

            if self.log_requests or True:
                self.module.log(pformat(dict(url=request_url, data=data, method=method)))

            return request(url=request_url, data=data, method=method, headers=headers, use_proxy=True, force=False, last_mod_time=None,
                           timeout=self.DEFAULT_TIMEOUT, http_agent=self.HTTP_AGENT, force_basic_auth=True, ignore_errors=ignore_errors, **self.creds)


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=True, ignore_errors=False):
    """Issue an HTTP request to a url, retrieving an optional JSON response."""

    if headers is None:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update({"netapp-client-type": "Ansible-%s" % ansible_version})

    if not http_agent:
        http_agent = "Ansible / %s" % ansible_version

    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except HTTPError as err:
        r = err.fp

    try:
        raw_data = r.read()
        if raw_data:
            data = json.loads(raw_data)
        else:
            raw_data = None
    except Exception:
        if ignore_errors:
            pass
        else:
            raise Exception(raw_data)

    resp_code = r.getcode()

    if resp_code >= 400 and not ignore_errors:
        raise Exception(resp_code, data)
    else:
        return resp_code, data


class NetAppESeriesHostGroup(NetAppESeriesModule):
    EXPANSION_TIMEOUT_SEC = 10
    DEFAULT_DISK_POOL_MINIMUM_DISK_COUNT = 11

    def __init__(self):
        version = "02.00.0000.0000"
        ansible_options = dict(
            state=dict(required=True, choices=["present", "absent"], type="str"),
            name=dict(required=False, type="str"),
            new_name=dict(required=False, type="str"),
            id=dict(required=False, type="str"),
            hosts=dict(required=False, type="list"))
        mutually_exclusive = [["name", "id"]]
        super(NetAppESeriesHostGroup, self).__init__(ansible_options=ansible_options,
                                                     web_services_version=version,
                                                     supports_check_mode=True,
                                                     mutually_exclusive=mutually_exclusive)

        args = self.module.params
        self.state = args["state"]
        self.name = args["name"]
        self.new_name = args["new_name"]
        self.id = args["id"]
        self.hosts_list = args["hosts"]

        self.current_host_group = None

    @property
    def hosts(self):
        """Retrieve a list of host reference identifiers should be associated with the host group."""
        host_list = []
        existing_hosts = []

        if self.hosts_list:
            try:
                rc, existing_hosts = self.request("storage-systems/%s/hosts" % self.ssid)
            except Exception as error:
                self.module.fail_json(msg="Failed to retrieve hosts information. Array id [%s].  Error[%s]."
                                          % (self.ssid, to_native(error)))

            for host in self.hosts_list:
                for existing_host in existing_hosts:
                    if host in existing_host["id"] or host in existing_host["name"]:
                        host_list.append(existing_host["id"])
                        break
                else:
                    self.module.fail_json(msg="Expected host does not exist. Array id [%s].  Host [%s]."
                                              % (self.ssid, host))

        return host_list

    @property
    def host_groups(self):
        """Retrieve a list of existing host groups."""
        host_groups = []
        hosts = []
        try:
            rc, host_groups = self.request("storage-systems/%s/host-groups" % self.ssid)
            rc, hosts = self.request("storage-systems/%s/hosts" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve host group information. Array id [%s].  Error[%s]."
                                      % (self.ssid, to_native(error)))

        host_groups = [{"id": group["clusterRef"], "name": group["name"]} for group in host_groups]
        for group in host_groups:
            hosts_ids = []
            for host in hosts:
                if group["id"] == host["clusterRef"]:
                    hosts_ids.append(host["hostRef"])
            group.update({"hosts": hosts_ids})

        return host_groups

    @property
    def current_hosts_in_host_group(self):
        """Retrieve the current hosts associated with the current hostgroup."""
        current_hosts = []
        for group in self.host_groups:
            if (self.name and group["name"] == self.name) or (self.id and group["id"] == self.id):
                current_hosts = group["hosts"]

        return current_hosts

    def unassign_hosts(self, host_list=None):
        """Unassign hosts from host group."""
        if host_list is None:
            host_list = self.current_host_group["hosts"]

        for host_id in host_list:
            try:
                rc, resp = self.request("storage-systems/%s/hosts/%s/move" % (self.ssid, host_id),
                                        method="POST", data={"group": "0000000000000000000000000000000000000000"})
            except Exception as error:
                self.module.fail_json(msg="Failed to unassign hosts from host group. Array id [%s].  Host id [%s]."
                                          "  Error[%s]." % (self.ssid, host_id, to_native(error)))

    def delete_host_group(self, unassign_hosts=True):
        """Delete host group"""
        if unassign_hosts:
            self.unassign_hosts()

        try:
            rc, resp = self.request("storage-systems/%s/host-groups/%s" % (self.ssid, self.current_host_group["id"]),
                                    method="DELETE")
        except Exception as error:
            self.module.fail_json(msg="Failed to delete host group. Array id [%s].  Error[%s]."
                                      % (self.ssid, to_native(error)))

    def create_host_group(self):
        """Create host group."""
        data = {"name": self.name, "hosts": self.hosts}

        response = None
        try:
            rc, response = self.request("storage-systems/%s/host-groups" % self.ssid, method="POST", data=data)
        except Exception as error:
            self.module.fail_json(msg="Failed to create host group. Array id [%s].  Error[%s]."
                                      % (self.ssid, to_native(error)))

        return response

    def update_host_group(self):
        """Update host group."""
        data = {"name": self.new_name if self.new_name else self.name,
                "hosts": self.hosts}

        # unassign hosts that should not be part of the hostgroup
        desired_host_ids = self.hosts
        for host in self.current_hosts_in_host_group:
            if host not in desired_host_ids:
                self.unassign_hosts([host])

        update_response = None
        try:
            rc, update_response = self.request("storage-systems/%s/host-groups/%s"
                                               % (self.ssid, self.current_host_group["id"]), method="POST", data=data)
        except Exception as error:
            self.module.fail_json(msg="Failed to create host group. Array id [%s].  Error[%s]."
                                      % (self.ssid, to_native(error)))

        return update_response

    def apply(self):
        """Apply desired host group state to the storage array."""
        changes_required = False

        # Search for existing host group match
        for group in self.host_groups:
            if (self.id and group["id"] == self.id) or (self.name and group["name"] == self.name):
                self.current_host_group = group

        # Determine whether changes are required
        if self.state == "present":
            if self.current_host_group:
                if (self.new_name and self.new_name != self.name) or self.hosts != self.current_host_group["hosts"]:
                    changes_required = True
            else:
                if not self.name:
                    self.module.fail_json(msg="The option name must be supplied when creating a new host group."
                                              " Array id [%s]." % self.ssid)
                changes_required = True

        elif self.current_host_group:
            changes_required = True

        # Apply any necessary changes
        msg = ""
        if changes_required and not self.module.check_mode:
            msg = "No changes required."
            if self.state == "present":
                if self.current_host_group:
                    if ((self.new_name and self.new_name != self.name) or
                            (self.hosts != self.current_host_group["hosts"])):
                        msg = self.update_host_group()
                else:
                    msg = self.create_host_group()

            elif self.current_host_group:
                self.delete_host_group()
                msg = "Host group deleted. Array Id [%s].  Host Name [%s].  Host Id [%s]."\
                      % (self.ssid, self.current_host_group["name"], self.current_host_group["id"])

        self.module.exit_json(msg=msg, changed=changes_required)


def main():
    hostgroup = NetAppESeriesHostGroup()
    hostgroup.apply()


if __name__ == "__main__":
    main()
