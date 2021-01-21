from lib import common_utils
from lib import cli


def main():
    args = cli.parse()
    if args.attack_ext_id:
        common_utils.get_mitigations(args.attack_ext_id)


if __name__ == "__main__":
    main()
