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
        self.filter_rules       = self.init_rules()

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
            graph.add_node("s{0}".format(subnet_id), id=subnet_id,
                address=subnet['address'], prefix=subnet['prefix']
            )
        
        # add edges to graph
        for edge in self.__network_desc['links']:
            '''
            add edge from router to subnet
            edge attributes: 
                interfaceId: the id of the interface on the router (unique per router)
                ip: the ip of the interface on the router (unique per router)
            '''
            graph.add_edge(
                "r{0}".format(edge['routerId']),
                "s{0}".format(edge['subnetId']),
                interfaceId=edge['interfaceId'],
                ip=edge['ip']
            )

        return graph

    def generate_filter_rule(self, communication):
        '''
        Generates the filter rules for the given communication object
        
        Args:
            communication (dict): A dict with the communication parameters
        '''


        if communication['direction'] == 'bidirectional':
            pass


    def init_rules(self):
        '''
        Initializes the basic filter rules for each router and writes them into self.filter_rules
        '''
        for router in self.__network_desc['routers']:
            self.filter_rules[router['id']] = {
                '*nat': [
                    ':OUTPUT ACCEPT [0:0]',
                    ':PREROUTING ACCEPT [0:0]',
                    ':POSTROUTING ACCEPT [0:0]','
                    'COMMIT'
                ],
                '*filter': [
                    ':INPUT DROP [0:0]',
                    ':OUTPUT DROP [0:0]',
                    ':FORWARD DROP [0:0]'
                ]
            }