# Firewall Rule Generator

This project was part of the Network Security course at ETH Zurich. 
The goal was to create a program that receives a network description and a
set of allowed communications and produces the correct iptables rules for each router in
the network, such that no unallowed communication is possible.

## Getting Started

Clone the project

```bash
git clone https://github.com/ymerkli/firewall-rule-generator
```

### Prerequisites

The project requires Python 3 and networkx
```bash
pip3 install networkx
```

## Inputs
Inputs are JSON files, describing a network and its allowed communications. Networks are undirected bipartite graphs of routers and subnets. A link
can only exist between routers and subnets. The network is also a tree.

Input testcases are given in the `inputs` folder.

## Outputs
The outputs are the iptables rules for each router in the network. Output files are in the iptables restore file format and will be stored in the `output/<test_id>` folder.

## Run testcases

Run all testcases
```bash
sudo bash run -i INPUT_DIR -o OUTPUT_DIR
```

Run a single testcase
```bash
sudo python3 main.py -i INPUT_DIR -o OUTPUT_DIR -t TESTCASE_ID
```

where:
  * `INPUT_DIR` (optional, default = inputs/)

    Path to the directory with input files. Test cases in it should be named :id.json, where :id is the test-case ID.

  * `OUTPUT_DIR` (optional, default = outputs/)

    Path to directory where output files are written to. If this directory does
    not yet exist, it will be created. The content of this directory follows
    the pattern output/:testcaseId/:routerId.

  * `TESTCASE_ID` (optional)

    If present, only this testcase from INPUT_DIR will be processed.