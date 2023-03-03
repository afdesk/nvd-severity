from typing import Literal, TypedDict, Optional

CvssData = TypedDict("CvssData", {
    "Severity": str,
    "Score": float,
    "Cvss_v20_vector": Optional[str],
    "Cvss_v30_vector": Optional[str],
    "Cvss_v31_vector": Optional[str]
})


class CveMapper:
    def map(self, vulnerability):
        return {
            "Description": self._extract_description(vulnerability),
            **self._extract_cvss_data(vulnerability)
        }

    def _get_cvss_by_source_type(self, source_type: Literal['Primary', 'Secondary'], cvss_list):
        return next(filter(lambda x: x["type"] == source_type, cvss_list), None)

    def _extract_cvss_data(self, cve) -> CvssData:
        cvss_data: CvssData = {
            "Severity": "UNKNOWN",
            "Score": 0.0
        }

        metrics = cve.get("metrics", {})

        cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2")))
        if cvss_list:
            cvss = self._get_cvss_by_source_type("Primary", cvss_list)
            if cvss is None:
                cvss = self._get_cvss_by_source_type("Secondary", cvss_list)
            nvd_cvss_data = cvss["cvssData"]
            if nvd_cvss_data["version"] == "2.0":
                base_severity = cvss.get("baseSeverity")
            else:
                base_severity = nvd_cvss_data.get("baseSeverity")
            cvss_data["Severity"] = base_severity
            vector = nvd_cvss_data["vectorString"]
            version = nvd_cvss_data["version"].replace(".", "")
            vector_key = f"Cvss_v{version}_vector"
            cvss_data[vector_key] = vector
            cvss_data["Score"] = nvd_cvss_data["baseScore"]

        return cvss_data

    def _extract_description(self, cve) -> str:
        return [d["value"] for d in cve["descriptions"] if d["lang"] == "en"][0]

cveMapper = CveMapper()
