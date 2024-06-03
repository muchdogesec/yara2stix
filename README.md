# yarastix

A command line tool that converts the YARA Rules into STIX 2.1 Objects.

## Before you get started

If you do not want to backfill, maintain, or support your own YARA STIX objects check out CTI Butler which provides a fully manage database of these objects and more!

https://www.ctibutler.com/

## Overview

> YARA is a tool aimed at (but not limited to) helping malware researchers to identify and classify malware samples. With YARA you can create descriptions of malware families (or whatever you want to describe) based on textual or binary patterns. Each description, a.k.a. rule, consists of a set of strings and a boolean expression which determine its logic.

[YARA Docs](https://yara.readthedocs.io/en/stable/index.html)

YARA rules are easy to write and understand, and they have a syntax that resembles the C language.

The public rules (approved by the YARA team) are stored in the main YARA repository: https://github.com/Yara-Rules/rules . Each rule is distributed as a `.yar` files.

You can see an example YARA Rule here: https://github.com/Yara-Rules/rules/blob/master/antidebug_antivm/antidebug_antivm.yar

Here at Signals Corps, most of the data we deal with is in STIX 2.1 format. This is because downstream threat intelligence tools understand STIX.

Therefore yara2stix works by converting YARA Rules to STIX 2.1 objects.

yara2stix provides two modes:

1. downloads the latest rules from the [Yara-Rules/rules repository](https://github.com/Yara-Rules/rules) and converts each rule into a range of STIX objects
2. accepts a YARA rule in a .yar file and converts to a STIX indicator object

## Installing the script

To install yara2stix;

```shell
# clone the latest code
git clone https://github.com/muchdogesec/yara2stix
# create a venv
cd yara2stix
python3 -m venv yara2stix-venv
source yara2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

## Running the script

### Mode 1: Yara-Rules/rules repository -> STIX

```shell
python3 yara2stix.py \
	--mode yararules-repo
```

Where;

* `mode` (required): should always be `yararules-repo` if you want to download the latest rules from the [Yara-Rules/rules](https://github.com/Yara-Rules/rules). The latest commit on master will always be used.

On each run all objects will be regenerated in the `stix2_objects` directory.

Note, [you can easily download historic YARA data from our cti_knowledge_base repository so you don't have to run this script](https://github.com/muchdogesec/cti_knowledge_base_store).

### Mode 2: YARA YAR file -> STIX

```shell
python3 yara2stix.py \
	--mode yara-yar \
	--file PATH/TO/FILE.yar
```

Where;

* `mode` (required): should always be `yara-yar` if you want to convert a local YAR file
* `file` (required): is the path to the YAR file containing only the YARA Rule

e.g.

```shell
python3 yara2stix.py \
	--mode yara-yar \
	--file tests/demo_rules.yar
```

On each run all objects will be regenerated in the `stix2_objects` directory

## Mapping information

The public rules (approved by the YARA repo maintainers) are stored in the main YARA repository, nested as `.yar` in the directories;

* `antidebug_antivm`
* `capabilities`
* `crypto`
* `cve_rules`
* `deprecated`
* `email`
* `exploit_kits`
* `maldocs`
* `malware`
* `mobile_malware`
* `packers`
* `webshells`

This script does not consider any of the other directories in the repo.

### Marking Definition / Identity

These are hardcoded and imported from our [stix4doge repository](https://github.com/muchdogesec/stix4doge). Specifically these objects;

* Marking Definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/yara2stix.json
* Identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/yara2stix.json

### Indicators

Inside each of the directories above, there might be one or more `.yar` files.

Each `.yar` file might contain one or more rules.

Each rule in the file starts with either;

`private rule` (e.g. https://github.com/Yara-Rules/rules/blob/master/antidebug_antivm/antidebug_antivm.yar#L7), or
`rule` (e.g. https://github.com/Yara-Rules/rules/blob/master/antidebug_antivm/antidebug_antivm.yar#L24)

Each YARA rule inside a `yar` file is converted into an Indicator as follows;

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<UUID V5 LOGIC>",
    "created_by_ref": "<IDENTITY IMPORTED>",
    "created": "<DATE / FIRST COMMIT TIME OF FILE / SCRIPT EXECTION>",
    "modified": "<DATE / FIRST COMMIT TIME OF FILE / SCRIPT EXECTION>",
    "indicator_types": [
        "malicious-activity",
        "anomalous-activity"
    ],
    "name": "<PART IMMEDITELY AFTER THE RULE ENTRY>",
    "description": "<DESCRIPTION VALUE, ELSE BLANK>",
    "pattern": "<ENTIRE YARA RULE>",
    "pattern_type": "yara",
    "valid_from": "<CREATED TIME>",
    "external_references": [
        {
            "source_name": "rule",
            "url": "<GITHUB LINK TO RULE>"
        },
        {
            "source_name": "reference",
            "url": "<YARA RULE REFERENCE VALUE>"
        },
        {
            "source_name": "author",
            "url": "<YARA RULE AUTHOR VALUE>"
        }
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]      
}
```

The UUID part of the rule is generated using the namespaces `2c741473-e0f1-5f0a-a044-ae2a368ad0c6` and the YARA Rule `GITHUB LINK+name+pattern_type` (from STIX object).

e.g. `https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar+Big_Numbers0+yara` = `907116cb-0e98-5aa2-bbf2-741f3477f3d4` = `indicator--907116cb-0e98-5aa2-bbf2-741f3477f3d4`

#### A short note on `created` and `modified` properties

Where possible we use the `date` field found in the rules as the `created` and `modified` properties of the STIX object.

If no date is found in the rule (or the date format is not understood) the script will use either the commit time (if `yararules-repo`) or the script execution time (if `yara-yar`).

### Grouping

To represent the file all the rules are found in a STIX grouping object is used...

```json
{
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--<UUID V5>",
    "created_by_ref": "<IDENTITY IMPORTED>",
    "created": "<EARLIEST MODIFIED TIME OF OBJECT IN GROUP>",
    "modified": "<LATEST MODIFIED TIME OF OBJECT IN GROUP>",
    "name": "<DIRECTORY PATH AND FILE>",
    "context": "suspicious-activity",
    "object_refs": [
        "indicator--<ID OF RULE IN YAR FILE>",
        "indicator--<ID OF RULE IN YAR FILE>"
    ],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "<MARKING DEFINITION IMPORTED>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `2c741473-e0f1-5f0a-a044-ae2a368ad0c6` and `name` property.

e.g, `rules/antidebug_antivm` = `1c303523-b8ff-57aa-990f-c1cc43b43a25` = `grouping--1c303523-b8ff-57aa-990f-c1cc43b43a25`

As a real example, this directory path holds 14 rules: https://github.com/Yara-Rules/rules/tree/master/cve_rules, and thus 14 `object_refs` would exist in the grouping object representing it.

### Bundle

yara2stix also creates a STIX 2.1 Bundle JSON object containing all the STIX 2.1 Objects created at each run. The Bundle takes the format;

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5 GENERATION LOGIC>",
    "objects": [
        "<ALL STIX JSON OBJECTS>"
    ]
}
```

To generate the id of the SRO, a UUIDv5 is generated using the namespace `2c741473-e0f1-5f0a-a044-ae2a368ad0c6` and `<MD5 HASH OF THE SORTED OBJECTS PAYLOAD IN BUNDLE JSON>`.

The bundle is called: yara-rule-bundle.json

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [Yara-Rules on GitHub](https://github.com/Yara-Rules/rules)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).