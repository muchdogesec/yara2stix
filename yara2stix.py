import argparse
from src.yara2stix import Yara2Stix
from pathlib import Path


def filetype(file):
    path = Path(file)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"{path.absolute()} is not a file")
    return path

parser = argparse.ArgumentParser(description='Run Sigma2Stix with specific Sigma version tag.')
parser.add_argument('--mode', choices=["yararules-repo", "yara-yar"], required=True)
fileaction = parser.add_argument('--file', type=filetype, nargs='+')
args = parser.parse_args()

if args.mode == "yara-yar" and not args.file:
    parser.error(f"{'/'.join(fileaction.option_strings)} is required in mode {args.mode}")
print(__import__("json").dumps(__import__("sys").argv[1:]))
Yara2Stix().run(args.mode, args.file)