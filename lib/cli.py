import argparse


def parse():
    parser = argparse.ArgumentParser(description='Attack Mitigation Mapper')
    required = parser.add_argument_group('required named arguments')
    required.add_argument('--attack-id', dest="attack_ext_id", help='Attack Pattern id e.g. T1548', required=True)
    args = parser.parse_args()
    return args
