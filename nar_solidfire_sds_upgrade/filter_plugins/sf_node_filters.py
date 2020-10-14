#!/usr/bin/python

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleFilterError
from ansible.utils.display import Display

display = Display()


class FilterModule(object):
    """Custom filters for SF Cluster/Node info"""

    def filters(self):
        """
        Available filters from this custom filter

        :return dict:
        """
        return {
            'sf_get_node_ids': self.get_node_ids,
            'sf_get_cluster_nodes': self.get_node_list,
            'sf_get_node_name': self.get_field_from_identifier,
            'sf_get_node_info': self.get_field_from_identifier,
            'sf_change_timeout': self.change_maint_mode_timeout
        }

    def change_maint_mode_timeout(self, current, add):
        """
        Adds the supplied value (add) to the current and generates a new
        HH:MM:SS timeout value for the EnableMaintenanceMode API to use

        :param str current: Old timeout (supplied as 'HH:MM:SS')
        :param str add: Timeout value to add (supplied as 'HH:MM:SS')

        :return str: Returns the new timeout value in 'HH:MM:SS' format

        :raises AnsibleFilterError:
        """
        # Convert current time to a number of seconds
        try:
            h, m, s = [int(i) for i in current.split(':')]
            current_secs = (3600 * h + 60 * m + s)
        except ValueError as exp:
            raise AnsibleFilterError(
                "Invalid timeout format. Received '{}', need 'HH:MM:SS': {}"
                .format(current, exp))
        except AttributeError as exp:
            raise AnsibleFilterError(
                "No data found for the timeout value: {}"
                .format(exp))

        # Convert the time to add into a number of seconds
        try:
            h, m, s = [int(i) for i in add.split(':')]
            adding_secs = (3600*h + 60*m + s)
        except ValueError as exp:
            raise AnsibleFilterError(
                "Invalid format for value to add. Received '{}', need 'HH:MM:SS': {}"
                .format(current, exp))
        except AttributeError as exp:
            raise AnsibleFilterError(
                "No data found for the time to add: {}"
                .format(exp))

        # Generate the new # of seconds to wait
        new_timeout = current_secs + adding_secs

        # Create the timeout as # of hours (in seconds)
        hours, remainder = divmod(new_timeout, 3600)

        # Take the remainder and create the # of minutes and seconds
        minutes, seconds = divmod(remainder, 60)

        # Return the timeout in the expected string format (same as: '%H:%M:%S')
        return '{:02}:{:02}:{:02}'.format(int(hours), int(minutes), int(seconds))

    def get_field_from_identifier(self, node_identifier, sf_node_list, field_name='name'):
        """
        Uses the name, sip, or mip, or nodeID to return the specific NodeInfo field
        from the ListAllNodes payload

        :param int|ipaddr|str node_identifier: The Identifier to return the node ID for
        :param list sf_node_list: List of nodes from the ListAllNodes API
        :param str field_name: The field to return (default: name)

        :return str: The name of the specified cluster member

        :raises AnsibleFilterError:
        """
        node_name = ""

        # Iterate through the list of nodes in the cluster
        for sf_node in sf_node_list:

            if field_name not in sf_node.keys():
                raise AnsibleFilterError(
                    '{} is not a valid ListAllNodes payload field'.format(field_name)
                )

            try:
                # Check for errors in the received data
                self._check_for_errors(sf_node, node_identifier)
            except Exception as exp:
                # Re-raise the AnsibleFilterError exception
                raise exp

            # Generate a list of node identifiers
            node_id_list = [
                sf_node['mip'],
                sf_node['sip'],
                sf_node['name'],
                sf_node['nodeID']
            ]

            # Exit the loop as soon as we match the identifier
            if node_identifier in node_id_list:
                # Save the name of the node
                node_name = sf_node[field_name]
                break

        return node_name

    def _check_for_errors(self, node_info, node_identifier):
        """
        Trigger exceptions if the data in the node info is bad/missing.
        This is a _total_ belt and suspenders moment. It should _never_ happen!

        :param dict node_info: The dictionary of node info from the cluster
        :param str node_identifier: The identifier we're looking for
        :return None:

        :raises AnsibleFilterError:
        """
        # NodeID is empty (should only happen if it's not a cluster member)
        if 'nodeID' not in node_info or not node_info['nodeID']:
            raise AnsibleFilterError(
                '{} does not have a node ID specified in the cluster'
                .format(node_identifier)
            )

        # Name field is empty (should never happen!)
        if 'name' not in node_info or not node_info['name']:
            raise AnsibleFilterError(
                '{} does not have a name configured!'
                .format(node_identifier)
            )

        # SIP field is empty (should never happen!)
        if 'sip' not in node_info or not node_info['sip']:
            raise AnsibleFilterError(
                '{} does not have a SPI configured!'
                .format(node_identifier)
            )

        # MIP field is empty (should never happen!)
        if 'mip' not in node_info or not node_info['mip']:
            raise AnsibleFilterError(
                '{} does not have a MIP configured!'
                .format(node_identifier)
            )

    def get_node_ids(self, sf_node_list):
        """Uses the ListAllNodes API payload to get the nodeID and return a list of them

        :param list sf_node_list: The list of node data from the SF \
        cluster's ListAllNodes API

        :return: Node IDs for the cluster
        :rval dict: Node SIP -> Node ID mapping

        :raises AnsibleFilterError:
        """
        sf_node_ids = dict()

        # Loops through the JSON payload and creates a dict
        # w/node name (uppercase) and Node ID in cluster
        for sf_node in sf_node_list:
            if not sf_node['nodeID']:
                raise AnsibleFilterError(
                    '{} does not have a node ID specified in the cluster'
                    .format(sf_node["sip"])
                )

            sf_node_ids[sf_node["sip"].upper()] = sf_node['nodeID']

        return sf_node_ids

    def get_node_list(self, sf_node_list):
        """
        Return list of node names for the cluster

        :param list sf_node_list: The list of node data from the SF cluster

        :return: The list of node names that are cluster members
        :rval list:

        :raises AnsibleFilterError:
        """

        sf_nodes = list()

        # Iterate through the list of nodes in the cluster
        for sf_node in sf_node_list:

            # This shouldn't happen, but just in case
            if not sf_node['name']:
                raise AnsibleFilterError('Node does not have a name configured!')

            # Save the name of the nodes to the list of cluster members
            sf_nodes.append(sf_node['name'])

        return sf_nodes
