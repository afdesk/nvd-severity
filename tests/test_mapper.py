import json
from pathlib import Path

from nvd_severity.mapper import cveMapper

test_data_path = Path(__file__).parent / "test_data"


def load_test_file(file_name):
    with (test_data_path / file_name).open(mode="r") as f:
        return json.load(f)


def load_and_map(file_name):
    return cveMapper.map(load_test_file(file_name))


def test_map_cvssV2():
    model = load_and_map("cvss_v2.json")

    assert model == {
        "Description": "The debug command in Sendmail is enabled, allowing attackers to execute commands as root.",
        "Severity": "HIGH",
        "Score": 10,
        "Cvss_v20_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    }


def test_map_cvssV30():
    model = load_and_map("cvss_v30_and_v2.json")

    assert model == {
        "Description": "IIS 4.0 and 5.0 allows remote attackers to cause a denial of service by sending many URLs with a large number of escaped characters, aka the \"Myriad Escaped Characters\" Vulnerability.",
        "Severity": "HIGH",
        "Score": 7.5,
        "Cvss_v30_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }


def test_map_cvssV31():
    model = load_and_map("cvss_v31_and_v2.json")

    assert model == {
       "Description": "ScriptAlias directory in NCSA and Apache httpd allowed attackers to read CGI programs.",
       "Severity": "HIGH",
       "Score": 7.5,
       "Cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
   }


def test_map_cve_with_secondary():
    model = load_and_map("cve_with_secondary.json")

    assert model == {
       "Description": "** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in ISS BlackICE PC Protection and classified as critical. Affected by this issue is the component Cross Site Scripting Detection. The manipulation as part of POST/PUT/DELETE/OPTIONS Request leads to privilege escalation. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.",
       "Severity": "CRITICAL",
       "Score": 9.8,
       "Cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   }


def test_map_cve_only_secondary():
    model = load_and_map("cve_only_secondary.json")

    assert model == {
       "Description": "** UNSUPPORTED WHEN ASSIGNED ** A vulnerability was found in ISS BlackICE PC Protection and classified as critical. Affected by this issue is the component Cross Site Scripting Detection. The manipulation as part of POST/PUT/DELETE/OPTIONS Request leads to privilege escalation. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.",
       "Severity": "MEDIUM",
       "Score": 5.3,
       "Cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
   }