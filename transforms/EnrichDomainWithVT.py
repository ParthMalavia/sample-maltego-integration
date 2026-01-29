import requests
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform
from extensions import registry
from settings import api_key_setting


@registry.register_transform(
    display_name="Enrich Domain with VirusTotal Report",
    input_entity="maltego.Domain",
    description="Fetches VirusTotal domain report and adds subdomains as new entities",
    output_entities=["maltego.Domain"],
)
class EnrichDomainWithVT(DiscoverableTransform):
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        response.addUIMessage(f"Debug: Input Value = {repr(request.Value)}", messageType="Inform")
        try:
            domain = request.Value.strip()
            api_key = request.getTransformSetting(api_key_setting.name)
            if not api_key:
                response.addUIMessage("VirusTotal API key is required.", messageType="PartialError")
                return

            headers = {"x-apikey": api_key}
            base_url = "https://www.virustotal.com/api/v3"

            # ---------- 1. Domain report ----------
            report_url = f"{base_url}/domains/{domain}"
            report_resp = requests.get(report_url, headers=headers)
            if report_resp.status_code != 200:
                response.addUIMessage(
                    f"Error fetching report: {report_resp.status_code} - {report_resp.text}",
                    messageType="PartialError",
                )
                return
            report_data = report_resp.json().get("data", {}).get("attributes", {})

            # ---------- 2. Enrich the original domain ----------
            enriched_entity = response.addEntity("maltego.Domain", domain)

            # ---- last_analysis_stats ----
            if "last_analysis_stats" in report_data:
                stats = report_data["last_analysis_stats"]
                enriched_entity.addProperty(fieldName="vt.malicious", displayName="VT Malicious Detections",
                                          value=str(stats.get("malicious", 0)))
                enriched_entity.addProperty(fieldName="vt.suspicious", displayName="VT Suspicious Detections",
                                          value=str(stats.get("suspicious", 0)))
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                timeout = stats.get("timeout", 0)
                enriched_entity.addDisplayInformation(
                    f"<b>Malicious:</b> {malicious} <b>Suspicious:</b> {suspicious} "
                    f"<i>Undetected:</i> {undetected} <i>Harmless:</i> {harmless} <i>Timeout:</i> {timeout}",
                    "VT Analysis Stats"
                )

            # ---- reputation ----
            if "reputation" in report_data:
                reputation = report_data["reputation"]
                enriched_entity.addProperty(fieldName="vt.reputation", displayName="VT Reputation Score",
                                          value=str(reputation))
                enriched_entity.addDisplayInformation(
                    f"<b>Reputation Score:</b> {reputation} <i>(Higher is better)</i>",
                    "VT Reputation"
                )

            # ---- categories ----
            if "categories" in report_data:
                categories = ", ".join(report_data["categories"].values())
                enriched_entity.addProperty(fieldName="vt.categories", displayName="VT Categories",
                                          value=categories)
                enriched_entity.addDisplayInformation(
                    f"<b>Categories:</b> {categories}",
                    "VT Categories"
                )

            # ---- whois ----
            if "whois" in report_data:
                whois_trunc = report_data["whois"][:500]
                enriched_entity.addProperty(fieldName="vt.whois", displayName="VT WHOIS",
                                          value=whois_trunc)
                enriched_entity.addDisplayInformation(
                    f"<b>WHOIS Preview:</b> {whois_trunc[:150]}...",
                    "VT WHOIS"
                )

            # ---- threat_severity ----
            if "threat_severity" in report_data:
                ts = report_data["threat_severity"]
                enriched_entity.addProperty(fieldName="vt.threat_severity_level",
                                          displayName="VT Threat Severity Level",
                                          value=ts.get("threat_severity_level", "Unknown"))
                enriched_entity.addProperty(fieldName="vt.threat_level_description",
                                          displayName="VT Threat Level Description",
                                          value=ts.get("level_description", ""))
                tsd = ts.get("threat_severity_data", {})
                enriched_entity.addProperty(fieldName="vt.threat_bad_com_files_high",
                                          displayName="VT Bad Communicating Files High",
                                          value=str(tsd.get("has_bad_communicating_files_high", False)))
                enriched_entity.addProperty(fieldName="vt.threat_bad_collection",
                                          displayName="VT Belongs to Bad Collection",
                                          value=str(tsd.get("belongs_to_bad_collection", False)))
                enriched_entity.addProperty(fieldName="vt.threat_actor",
                                          displayName="VT Belongs to Threat Actor",
                                          value=str(tsd.get("belongs_to_threat_actor", False)))
                enriched_entity.addProperty(fieldName="vt.threat_domain_rank",
                                          displayName="VT Domain Rank",
                                          value=tsd.get("domain_rank", "Unknown"))

                level = ts.get("threat_severity_level", "Unknown")
                desc = ts.get("level_description", "No description")
                enriched_entity.addDisplayInformation(
                    f"<b>Threat Severity Level:</b> {level} <i>Description:</i> {desc}",
                    "VT Threat Severity"
                )

            # ---- gti_assessment ----
            if "gti_assessment" in report_data:
                gti = report_data["gti_assessment"]
                enriched_entity.addProperty(fieldName="vt.gti_verdict", displayName="VT GTI Verdict",
                                          value=gti.get("verdict", {}).get("value", "Unknown"))
                enriched_entity.addProperty(fieldName="vt.gti_threat_score", displayName="VT GTI Threat Score",
                                          value=str(gti.get("threat_score", {}).get("value", 0)))
                enriched_entity.addProperty(fieldName="vt.gti_severity", displayName="VT GTI Severity",
                                          value=gti.get("severity", {}).get("value", "Unknown"))
                cf = gti.get("contributing_factors", {})
                enriched_entity.addProperty(fieldName="vt.gti_mandiant_confidence",
                                          displayName="VT GTI Mandiant Confidence Score",
                                          value=str(cf.get("mandiant_confidence_score", 0)))
                enriched_entity.addProperty(fieldName="vt.gti_mandiant_benign",
                                          displayName="VT GTI Mandiant Analyst Benign",
                                          value=str(cf.get("mandiant_analyst_benign", False)))
                enriched_entity.addProperty(fieldName="vt.gti_description",
                                          displayName="VT GTI Description",
                                          value=gti.get("description", ""))

                verdict = gti.get("verdict", {}).get("value", "Unknown")
                score = gti.get("threat_score", {}).get("value", 0)
                severity = gti.get("severity", {}).get("value", "Unknown")
                desc = gti.get("description", "No description")
                enriched_entity.addDisplayInformation(
                    f"<b>GTI Verdict:</b> {verdict} <b>Threat Score:</b> {score} "
                    f"<b>Severity:</b> {severity} <i>Description:</i> {desc}",
                    "VT GTI Assessment"
                )

            # ---------- 3. Subdomains ----------
            subdomains_url = f"{base_url}/domains/{domain}/subdomains?limit=10"
            subdomains_resp = requests.get(subdomains_url, headers=headers)
            if subdomains_resp.status_code == 200:
                for sub in subdomains_resp.json().get("data", []):
                    sub_domain = sub.get("id")
                    if sub_domain and sub_domain != domain:
                        new_entity = response.addEntity("maltego.Domain", sub_domain)
                        new_entity.addProperty(fieldName="vt.source", displayName="From VT Subdomain",
                                              value="VirusTotal")
                        new_entity.addDisplayInformation(
                            f"<b>Subdomain:</b> {sub_domain} <i>(From {domain})</i>",
                            "VT Subdomain"
                        )
            else:
                response.addUIMessage(
                    f"Error fetching subdomains: {subdomains_resp.status_code}",
                    messageType="Inform",
                )

        except Exception as e:
            response.addUIMessage(f"Unexpected error: {str(e)}", messageType="PartialError")
