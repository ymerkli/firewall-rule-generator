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

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    for filename in os.listdir(input_dir):
        # check if the filename matches the ':id.json' naming
        match = re.match(r"(\d+)\.json", filename)
        if match:
            testcase_id = match.group(1)

            # create testcase_id output folder if not already existing
            if not os.path.exists("{0}/{1}".format(output_dir, testcase_id)):
                os.mkdir("{0}/{1}".format(output_dir, testcase_id))

            with open(os.path.join(input_dir, filename), 'r') as json_file:
                input_file = json.load(json_file)
            
            fw_rule_generator = FirewallRuleGenerator(
                input_file['network'], input_file['communications']
            )

            fw_rule_generator.create_filter_rules()
        
            fw_rule_generator.write_filter_rules(output_dir, testcase_id)

if __name__ == "__main__":
    main()