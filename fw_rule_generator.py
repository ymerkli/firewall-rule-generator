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

    def get_filter_rules(self):
        '''
        Generates all the filter rules for the provided network_config and
        the communications specification
        '''

        for communication in self.__communications:
            self.generate_filter_rule(communication)

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
        for edge in self.__network_desc['links']:
            '''
            add edge from router to subnet
            edge attributes: 
                interfaceId: the id of the interface on the router (unique per router)
                ip: the ip of the interface on the router (unique per router)
            '''
            router_name  = rId2sName(edge['routerId'])
            subnet_name  = sId2sName(edge['subnetId'])
            interface_id = edge['interfaceId']
            interface_ip = edge['ip']

            graph.add_edge(
                router_name,
                subnet_name,
                routerInterfaceId=interface_id,
                routerInterfaceIp=interface_ip
            )

            # add the information for the interface connected towards the subnet into the
            # router node. This makes things easier during rule creation
            graph.nodes[router_name][subnet_name] = {
                'interfaceId': interface_ip,
                'interfaceIp': interface_ip 
            } 

        return graph

    def generate_filter_rule(self, communication):
        '''
        Generates the filter rules for the given communication object
        
        Args:
            communication (dict): A dict with the communication parameters
        '''

        src_subnet = sId2sName(communication['sourceSubnetId']) 
        dst_subnet = sId2sName(communication['targetSubnetId'])

        path = nx.shortest_path(self.__graph, source=src_subnet, target=dst_subnet)

        # iterate over all hops and add rules to routers
        for i in range(len(path)):
            if re.match(r"r\d+", path[i]):
                # get the last and next hop. These will always be subnets
                # since router-router links dont exist
                # routers are never the first or last hop, thus the array access
                # will never be out of range

                router_name       = path[i]
                last_hop          = path[i-1]
                next_hop          = path[i+1]

                src_ip            = self.__graph.nodes[src_subnet]['address']
                src_prefix        = self.__graph.nodes[src_subnet]['prefix']
                dst_ip            = self.__graph.nodes[dst_subnet]['address']
                dst_prefix        = self.__graph.nodes[dst_subnet]['prefix']
                ingress_interface = self.__graph.nodes[router_name][last_hop]['interfaceId']
                egress_interface  = self.__graph.nodes[router_name][next_hop]['interfaceId']

                # construct the rule string
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
                    '--state NEW,ESTABLISHED '
                    '-j ACCEPT '
                ).format(
                    p=communication['protocol'],
                    sportStart=communication['sourcePortStart'],
                    sportEnd=communication['sourcePortEnd'],
                    dportStart=communication['targetPortStart'],
                    dportEnd=communication['targetPortEnd'],
                    srcIp=src_ip,
                    srcPrefix=src_prefix,
                    dstIp=dst_ip,
                    dstPrefix=dst_prefix,
                    ingressIf=ingress_interface,
                    egressIf=egress_interface,
                )


    def init_rules(self):
        '''
        Initializes the basic filter rules for each router and writes them into self.filter_rules
        '''

        for router in self.__network_desc['routers']:
            self.filter_rules[router['id']] = {
                '*nat': [
                    ':OUTPUT ACCEPT [0:0]',
                    ':PREROUTING ACCEPT [0:0]',
                    ':POSTROUTING ACCEPT [0:0]',
                    'COMMIT'
                ],
                '*filter': [
                    ':INPUT DROP [0:0]',
                    ':OUTPUT DROP [0:0]',
                    ':FORWARD DROP [0:0]'
                ]
            }

def sId2sName(subnet_id):
    '''
    Converts a subnet id to the subnet node names in the graphs: 's<id>'
    Args:
        subnet_id (int): The subnet id
    Returns:
        subnet_name (str): the subent node name
    '''
    return "s{0}".format(subnet_id)

def rId2sName(router_id):
    '''
    Converts a router id to the router node names in the graphs: 'r<id>'
    Args:
        router_id (int): The router id
    Returns:
        router_name (str): the router node name
    '''
    return "r{0}".format(router_id)