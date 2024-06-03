import glob
import logging
import os
from pathlib import Path
import shutil
from tqdm import tqdm
from .import config, parser, utils


class Yara2Stix:
    def __init__(self):
        self.tag = config.git_branch

    @staticmethod
    def prepare_bundle():
        utils.store_in_bundle(
            utils.append_data()
        )

    def run(self, mode, yarfiles:list[Path]):

        utils.clean_filesystem(config.temporary_path)
        utils.clean_filesystem(config.file_system_path)
        repo = None
        if mode == 'yararules-repo':
            logging.info("Cloning start")
            repo = utils.clone_github_repository(config.source_repo, config.temporary_path, tag_name=self.tag)
            utils.delete_extras()
            logging.info("Cloning end")
        elif mode == "yara-yar":
            Path(config.temporary_path).mkdir(exist_ok=True)
            for yarfile in yarfiles:
                shutil.copy(yarfile, config.temporary_path)
        yarfiles = list(map(Path, glob.glob(f"{config.temporary_path}/**/*.yar", recursive=True)))
        parser.parse_marking_definition()
        parser.parse_identity()

        if not yarfiles:
            raise Exception("no files to parse")

        for yarfile in tqdm(yarfiles):
            url = yarfile.relative_to(config.temporary_path)
            if repo:
                url = f"{config.source_repo}/blob/{config.git_branch}/{url}"
            indicators = parser.parse_indicators(yarfile, url, repo)
            config.fs.add(parser.parse_grouping(yarfile, indicators))
        self.prepare_bundle()
        utils.clean_filesystem(config.temporary_path)

