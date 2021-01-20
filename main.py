from lib import common_utils
import argparse


def get_mitigations(ext_id):
    print("Finding mitigations for attack-id [%s]" % ext_id)
    url = common_utils.get_attack_url_by_id(ext_id)

    res = common_utils.execute('GET', url)

    mitigation_ids = common_utils.get_mitigations_from_html(res._content)
    print("Mitigation ids:", mitigation_ids)

    for mit_id in mitigation_ids:
        common_utils.display_mitigation_by_ids(mit_id)


def main():
    parser = argparse.ArgumentParser(description='Attack Mitigation Mapper')
    required = parser.add_argument_group('required named arguments')
    required.add_argument('--attack-id', dest="ext_id", help='Attack Pattern id e.g. T1548', required=True)
    args = parser.parse_args()
    get_mitigations(ext_id=str(args.ext_id))


if __name__ == "__main__":
    # get_mitigations("T1548")
    main()
