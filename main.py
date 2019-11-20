#!/usr/bin/env python3.6
import os
import argparse
import time
import io
import re
import json

from fw_rule_generator import FirewallRuleGenerator

def parser():
    parser = argparse.ArgumentParser(description='parse the keyword arguments')

    parser.add_argument(
        '-i',
        type=str,
        required=False,
        default='inputs/',
        help='The path to the directory with input files'
    )

    parser.add_argument(
        '-o',
        type=str,
        required=False,
        default='outputs/',
        help='The path to directory where output files will be written to'
    )

    args = parser.parse_args()

    return args.i, args.o

def main():
    # get the CLI arguments
    input_dir, output_dir = parser()

    for filename in os.listdir(input_dir):
        # check if the filename matches the ':id.json' naming
        if re.match(r"\d+\.json", filename):
            with open(os.path.join(input_dir, filename), 'r') as json_file:
                input_file = json.load(json_file)
            
        fw_rule_generator = FirewallRuleGenerator(
            input_file['network'], input_file['communications']
        )

        fw_rule_generator.get_filter_rules()




if __name__ == "__main__":
    main()