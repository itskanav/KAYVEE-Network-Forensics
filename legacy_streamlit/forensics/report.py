import json
import pandas as pd
from datetime import datetime, timezone

def make_json_report(case_id, analyst, filename, size, digest, meta, packets, alerts):
    report={
        "project":"KAYVEE Network Forensics",
        "generated_utc":datetime.now(timezone.utc).isoformat(),
        "case_id":case_id,"analyst":analyst,
        "evidence":{"filename":filename,"size_bytes":size,"sha256":digest},
        "parser_metadata":meta,
        "summary":{"packets_parsed":int(len(packets)),"unique_source_ips":int(packets["src_ip"].nunique()) if len(packets) else 0,
                   "unique_destination_ips":int(packets["dst_ip"].nunique()) if len(packets) else 0,"alerts":int(len(alerts))},
        "alerts":alerts.to_dict(orient="records"),
        "limitations":[
            "Heuristic alerts are not proof of malicious activity.",
            "This prototype does not decrypt TLS/HTTPS payloads.",
            "Conversation grouping is directional and does not perform full TCP stream reassembly.",
            "Threat-intelligence matching and TLS certificate validation require additional integrations/data."
        ]
    }
    return json.dumps(report,indent=2,default=str)

def make_csv_report(df):
    return df.to_csv(index=False)
