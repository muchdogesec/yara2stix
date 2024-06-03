import os
import shutil
import uuid
import json
import hashlib
import requests
from git import Repo
from typing import List
from .import config
from stix2 import Bundle
from stix2 import Filter
from pathlib import Path
from datetime import datetime as dt
from dateparser import _default_parser as dateparser

def clone_github_repository(repo_url, destination_path, tag_name):
    try:
        repo = Repo.clone_from(repo_url, destination_path, branch=tag_name)
        print(f"Repository cloned successfully to {destination_path}")
        return repo
    except Exception as e:
        print(f"Failed to clone repository: {e}")
        raise e


def check_dir(dir:str):
    if not os.path.exists(dir):
        os.makedirs(dir)

def clean_filesystem(path):
    try:
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
    except Exception as e:
        print(e)
        pass


def append_data():
    results = []
    for root, _, files in os.walk(config.file_system_path):
        for filename in files:
            if filename.endswith(".json"):
                file_path = os.path.join(root, filename)
                with open(file_path, "r") as file:
                    stix_object = json.load(file)
                    results.append(stix_object)
    return results


def generate_md5_from_list(stix_objects: list) -> str:
    json_str = json.dumps(stix_objects, sort_keys=True).encode('utf-8')
    return hashlib.md5(json_str).hexdigest()


def store_in_bundle(stix_objects):
    bundle_id = "bundle--" + str(uuid.uuid5(
        config.namespace, generate_md5_from_list(stix_objects))
    )
    bundle_of_all_objects = Bundle(id=bundle_id, objects=stix_objects)
    stix_bundle_file = f"{config.file_system_path}/yara-rule-bundle.json"
    print(f"writing output to {stix_bundle_file}")
    with open(stix_bundle_file, "w") as f:
        bundle_of_all_objects.fp_serialize(f, indent=4)

def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error loading JSON from {url}: {e}")
        return None


def get_data_from_fs(query:str):
    query = [Filter("type", "=", query)]
    return config.fs.query(query)


def get_commit_times(file_path:Path, repo: Repo=None):
    if not repo:
        time = dt.fromtimestamp(os.path.getctime(file_path))
        return time, time
    path_in_repo = file_path.absolute().relative_to(Path(repo.working_dir))
    commits = list(repo.iter_commits(paths=path_in_repo, max_count=1))
    created, modified = map(lambda commit: commit.authored_datetime, [commits[0], commits[-1]])
    return created, modified


def parse_date(date):
    if not date:
        return None
    datedata = dateparser.get_date_data(date, date_formats=["%d.%m.%Y", "%d.%m.%y"])
    print(datedata, date)
    if datedata.period == 'month': #if missing date, set date to 1
        datedata.date_obj = datedata.date_obj.replace(day=1)
    return datedata.date_obj


def delete_extras():
    temp_dir = Path(config.temporary_path)
    for d in os.listdir(temp_dir):
        if d.startswith("."):
            continue
        if d not in config.GIT_SUBDIRECTORIES:
            d = temp_dir/d
            if d.is_dir():
                shutil.rmtree(d)
            else:
                os.remove(d)
