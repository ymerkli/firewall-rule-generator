#!/usr/bin/env python3.6
import os
import argparse
import time
import io
import re
import json
import networkx as nx

class FirewallRuleGenerator(object):
    '''
    The FirewallRuleGenerator object generates firewall rules for 
    the provided network dict

    Attributes:
        network_config (dict):  A dict describing the network
        communications (array): An array with all the allowed communications
        graph (nx.graph()):     A nx.Graph object representing the network topology
        filter_rules (dict):    A dict with the filter rules to return. Keys are router_ids, values are
                                dicts: keys are table_name, value is an array of strings (rule) 
                                (order matters)
    '''

    def __init__(self, network_desc, communications):
        self.__network_desc     = network_desc
        self.__communications   = communications 
        self.__graph            = self.generate_network_graph()
        self.filter_rules       = {}

        self.init_rules()

    def generate_network_graph(self):
        '''
        Generates the specified network topology as a networkx.Graph object
        '''

        # the nx graph object representing the network topology
        graph = nx.Graph()

        # add router nodes to graph
        for router in self.__network_desc['routers']:
            router_id = router['id']

            '''
            router node naming convention:
            name: r<id>
            router node attributes: 
                router_id
            '''
            graph.add_node("r{0}".format(router_id), id=router_id)

        # add subnets nodes to graph
        for subnet in self.__network_desc['subnets']:
            subnet_id = subnet['id']

            '''
            subnet naming convention
            name: s<id>
            subnet node attributes: 
                subnet_id: the id of the subnet
                address: the network address
                prefix: the prefix of the network address
            '''
            graph.add_node(sId2sName(subnet_id), 
                id=subnet_id,
                address=subnet['address'], 
                prefix=subnet['prefix']
            )
        
        # add edges to graph
        for link in self.__network_desc['links']:
            '''
            add link from router to subnet
            edge attributes: 
                interfaceId: the id of the interface on the router (unique per router)
                ip: the ip of the interface on the router (unique per router)
            '''
            router_name  = rId2rName(link['routerId'])
            subnet_name  = sId2sName(link['subnetId'])
            interface_id = link['interfaceId']
            interface_ip = link['ip']

            graph.add_edge(
                router_name,
                subnet_name,
                routerInterfaceId=interface_id,
                routerInterfaceIp=interface_ip
            )

            # add the information for the interface connected towards the subnet into the
            # router node. This makes things easier during rule creation
            graph.nodes[router_name][subnet_name] = {
                'interfaceId': interface_id,
                'interfaceIp': interface_ip 
            } 

        return graph

    def create_filter_rules(self):
        '''
        Generates all the filter rules for the provided network_config and
        the communications specification and stores them in self.filter_rules
        '''

        for communication in self.__communications:
            communication_filter_rules = self.generate_filter_rule(communication)

            # iterate over all generate rules for the current communications object
            # and append the rules to each router's '*filter' rules array in self.filter_rules
            for router_name, rules_array in communication_filter_rules.items():
                self.filter_rules[router_name]['* filter'] += rules_array

    def generate_filter_rule(self, communication):
        '''
        Generates the filter rules for all routers on the communication path
        for the given communication object
        
        Args:
            communication (dict): A dict with the communication parameters

        Returns:
            filters_rules (dict): A dict with router names as keys and array with filter rules as values
        '''

        src_subnet = sId2sName(communication['sourceSubnetId']) 
        dst_subnet = sId2sName(communication['targetSubnetId'])

        path = nx.shortest_path(self.__graph, source=src_subnet, target=dst_subnet)

        # iterate over all hops and add rules to routers
        filter_rules = {}
        for i in range(len(path)):
            # check if the hop is a router (we only add rules for routers)
            if re.match(r"r\d+", path[i]):
                '''
                get the last and next hop. These will always be subnets
                since router-router links dont exist
                routers are never the first or last hop, thus the array access
                will never be out of range
                '''

                router_name                 = path[i]
                filter_rules[router_name]   = []

                last_hop          = path[i-1]
                next_hop          = path[i+1]

                protocol          = communication['protocol']
                sport_start       = communication['sourcePortStart']
                sport_end         = communication['sourcePortEnd']
                dport_start       = communication['targetPortStart']
                dport_end         = communication['targetPortEnd']
                src_ip            = self.__graph.nodes[src_subnet]['address']
                src_prefix        = self.__graph.nodes[src_subnet]['prefix']
                dst_ip            = self.__graph.nodes[dst_subnet]['address']
                dst_prefix        = self.__graph.nodes[dst_subnet]['prefix']
                ingress_interface = self.__graph.nodes[router_name][last_hop]['interfaceId']
                egress_interface  = self.__graph.nodes[router_name][next_hop]['interfaceId']

                rule = self.generate_rule_string(
                    protocol, sport_start, sport_end, dport_start, dport_end,
                    src_ip, src_prefix, dst_ip, dst_prefix, ingress_interface, egress_interface, 'NEW,ESTABLISHED'
                )
                filter_rules[router_name].append(rule)

                # if the communication is bidirectional, we add a rule with ports, IPs and
                # interfaces switched to allow the reverse communication 
                if communication['direction'] == 'bidirectional':
                    '''
                    In case of TCP and UDP, the bidirectional flag allows the target to send replies 
                    but not establish a new connection. the case of ICMP, both source and target are allowed 
                    to send packets irrespective of the connection state
                    '''
                    state = 'ESTABLISHED'
                    if protocol == 'icmp':
                        state = 'NEW,ESTABLISHED'

                    reverse_rule = self.generate_rule_string(
                        protocol, dport_start, dport_end, sport_start, sport_end,
                        dst_ip, dst_prefix, src_ip, src_prefix, egress_interface, ingress_interface, state 
                    )
                    filter_rules[router_name].append(reverse_rule)

        return filter_rules

    def generate_rule_string(
        self, protocol, sport_start, sport_end, dport_start, dport_end,
        src_ip, src_prefix, dst_ip, dst_prefix, ingress_interface, egress_interface, state 
    ):
        '''
        Generates the iptables rule string

        Args:
            protocol (str):             The L4 protocol (UDP, TCP)
            sport_start (int):          The lower bound of the --sport port range
            sport_end (int):            The upper bound of the --sport port range
            dport_start (int):          The lower bound of the --dport port range
            dport_end (int):            The upper bound of the --dport port range
            src_ip (str):               The IP of the src subnet
            src_prefix (int):           The prefix of the IP range of the src subnet
            dst_ip (str):               The IP of the dst subnet
            dst_prefix (int):           The prefix of the IP range of the dst subnet
            ingress_interface (str):    The interface where the traffic enters
            egress_interface (str):     The interface where the traffic leaves
            state (str):                The state to match (NEW, ESTABLISHED for forward rule, 
                                        ESTABLISHED for reverse rule)
        Returns:
            rule (str):                 The iptables rule string
        '''

        # check for ICMP, since ICMP doesnt have ports
        if protocol == 'icmp':
            rule = (
                '-A FORWARD '
                '-p {p} '
                '-s {srcIp}/{srcPrefix} '
                '-d {dstIp}/{dstPrefix} '
                '-i {ingressIf} '
                '-o {egressIf} '
                '-m state ' 
                '--state {state} '
                '-j ACCEPT '
            ).format(
                p=protocol,
                srcIp=src_ip,
                srcPrefix=src_prefix,
                dstIp=dst_ip,
                dstPrefix=dst_prefix,
                ingressIf=ingress_interface,
                egressIf=egress_interface,
                state=state
            )
        else:
            rule = (
                '-A FORWARD '
                '-p {p} '
                '--sport {sportStart}:{sportEnd} '
                '--dport {dportStart}:{dportEnd} '
                '-s {srcIp}/{srcPrefix} '
                '-d {dstIp}/{dstPrefix} '
                '-i {ingressIf} '
                '-o {egressIf} '
                '-m state ' 
                '--state {state} '
                '-j ACCEPT '
            ).format(
                p=protocol,
                sportStart=sport_start,
                sportEnd=sport_end,
                dportStart=dport_start,
                dportEnd=dport_end,
                srcIp=src_ip,
                srcPrefix=src_prefix,
                dstIp=dst_ip,
                dstPrefix=dst_prefix,
                ingressIf=ingress_interface,
                egressIf=egress_interface,
                state=state
            )

        return rule

    def init_rules(self):
        '''
        Initializes the basic filter rules for each router and writes them into self.filter_rules
        '''

        for router in self.__network_desc['routers']:
            router_name = "r{0}".format(router['id'])
            self.filter_rules[router_name] = {
                '* nat': [
                    ':OUTPUT ACCEPT [0:0]',
                    ':PREROUTING ACCEPT [0:0]',
                    ':POSTROUTING ACCEPT [0:0]',
                ],
                '* filter': [
                    ':INPUT DROP [0:0]',
                    ':OUTPUT DROP [0:0]',
                    ':FORWARD DROP [0:0]'
                ]
            }

    def write_filter_rules(self, output_dir, testcase_id):
        '''
        Writes all the rules in self.filter_rules to files in output_dir, follwing the
        iptables restore file format. Each router gets its own file.
        The content of the output_dir directory follows the pattern :testcaseId/:routerId

        Args:
            output_dir (str):   Path to the directory where output files are written to
            testcase_id (int):  The id of the testcase
        '''

        for router_name, table_dict in self.filter_rules.items():
            # extract router_id
            match = re.match(r"r(\d+)", router_name)
            if not match:
                raise ValueError("Invalid router name: {0}".format(router_name))
            router_id = match.group(1)

            # the output filename follows the pattern :output_dir/:testcaseId/:routerId
            output_file_name = "{0}/{1}/{2}".format(output_dir, testcase_id, router_id)
            if os.path.exists(output_file_name):
                os.remove(output_file_name)

            # the file handle to write the rules
            output_file = open(output_file_name, 'x')

            for table_name, rules_array in table_dict.items():
                output_file.write(table_name + "\n")

                # iterate over rules
                for rule in rules_array:
                    output_file.write(rule + "\n")

                output_file.write('\nCOMMIT\n\n')

            output_file.close()

def sId2sName(subnet_id):
    '''
    Converts a subnet id to the subnet node names in the graphs: 's<id>'
    Args:
        subnet_id (int): The subnet id
    Returns:
        subnet_name (str): the subent node name
    '''
    return "s{0}".format(subnet_id)

def rId2rName(router_id):
    '''
    Converts a router id to the router node names in the graphs: 'r<id>'
    Args:
        router_id (int): The router id
    Returns:
        router_name (str): the router node name
    '''
    return "r{0}".format(router_id)