import json
from types import SimpleNamespace

from stix2 import Indicator, Grouping, parse
from .import config, utils
import uuid
from pathlib import Path
import plyara, plyara.utils
from git import Repo
from datetime import datetime as dt


class YaraRules:
    __parser = plyara.Plyara(meta_as_kv=True)
    def __init__(self, yara_text):
        self.__parser.clear()
        self.__rules = self.__parser.parse_string(yara_text)
        self.__parsed_rules = []

    @property
    def rules(self):
        if self.__parsed_rules:
            return self.__parsed_rules
        for plyrule in self.__rules:
            self.__parsed_rules.append(SimpleNamespace(
                name=plyrule.get("rule_name"),
                metadata=self.get_rule_metadata(plyrule.get("metadata")),
                raw_text=plyara.utils.rebuild_yara_rule(plyrule)
            ))
        return self.__parsed_rules

    @staticmethod
    def get_rule_metadata(meta_kvp) -> dict():
        metadata = dict()
        if not meta_kvp:
            return metadata    
        for items in meta_kvp:
            k, v = next(iter(items.items()))
            metadata[k.lower()] = v
        return metadata


def parse_indicators(path:Path, url: str, repo: Repo):
    parser = YaraRules(path.read_text())
    rules  = parser.rules
    
    script_run_time = dt.now()
    repo_created, repo_modified = utils.get_commit_times(path, repo)
    indicators = []
    for rule in rules:
        metadata_date = utils.parse_date(rule.metadata.get("date"))
        if repo and not metadata_date:
            created, modified = repo_created, repo_modified
        else:
            created = modified = metadata_date or script_run_time
        id = str(uuid.uuid5(config.namespace, f"{url}+{rule.name}+yara"))
        indicator = Indicator(
            type="indicator",
            spec_version="2.1",
            id="indicator--"+id,
            created_by_ref=utils.get_data_from_fs("identity")[0],
            created=created,
            modified=modified,
            indicator_types=[
                "malicious-activity",
                "anomalous-activity"
            ],
            name=rule.name,
            description=rule.metadata.get("description"),
            pattern=rule.raw_text,
            pattern_type="yara",
            valid_from=created,
            external_references=[
                {
                    "source_name": "rule",
                    "url": url
                }] + 
                (rule.metadata.get("reference") and [
                {
                    "source_name": "reference",
                    "url": rule.metadata.get("reference")
                }] or []) + 
                (rule.metadata.get("author") and [{
                    "source_name": "author",
                    "url": rule.metadata.get("author")
                }] or []),

            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                utils.get_data_from_fs("marking-definition")[0]
            ]      
        )
        indicators.append(indicator)
        config.fs.add(indicator)
    return indicators


def parse_grouping(path: Path, indicators: list[Indicator]):
    if not indicators:
        return
    path = path.relative_to(config.temporary_path)
    created = indicators[0].modified
    object_refs = []
    for indicator in indicators:
        object_refs.append(indicator.id)
    name = f"{path.parent} AND " if str(path.parent) != "." else ""
    name += path.name 
    id = str(uuid.uuid5(config.namespace, name))
    grouping = Grouping(
        type="grouping",
        spec_version="2.1",
        id="grouping--"+id,
        created_by_ref=indicators[0].created_by_ref,
        created=created,
        modified=created,
        name=name,
        context="suspicious-activity",
        object_refs=object_refs,
        object_marking_refs=indicators[0].object_marking_refs
    )
    return grouping


def parse_marking_definition():
        marking_definition = parse(
            json.loads(utils.load_file_from_url(config.YARA2STIX_MARKING_DEFINITION_URL))
        )
        if not config.fs.get(marking_definition.get("id")):
            config.fs.add(marking_definition)
        return marking_definition

def parse_identity():
    identity = parse(
        json.loads(utils.load_file_from_url(config.YARA2STIX_IDENTITY_URL))
    )
    if not config.fs.get(identity.get("id")):
        config.fs.add(identity)
    return identity