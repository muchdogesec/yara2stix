import logging
from uuid import UUID
from stix2 import FileSystemStore
from .utils import check_dir
from dotenv import load_dotenv
import os

load_dotenv()

# logging.basicConfig(
#     level=logging.INFO,
#     format="[%(asctime)s] {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s",  # noqa D100 E501
#     datefmt="%Y-%m-%d - %H:%M:%S",
# )

namespace = UUID("2c741473-e0f1-5f0a-a044-ae2a368ad0c6")
source_repo = os.getenv("GIT_REPO_URL", "https://github.com/Yara-Rules/rules")
git_branch  = os.getenv("GIT_BRANCH", "master")
temporary_path = "data"
file_system_path = "stix2_objects"
check_dir(file_system_path)
fs = FileSystemStore(file_system_path)
GIT_SUBDIRECTORIES = ['antidebug_antivm', 'capabilities', 'crypto', 'cve_rules', 'deprecated', 'email', 'exploit_kits', 'maldocs', 'malware', 'mobile_malware', 'packers', 'webshells']
YARA2STIX_MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/yara2stix.json"
YARA2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/yara2stix.json"