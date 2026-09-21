import csv
import io


def build_csv(scan):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Severity", "Category", "Title", "Description", "Evidence", "Recommendation", "CVE References"])

    for f in scan.findings:
        cve_refs = ", ".join(c["id"] for c in f.to_dict()["cve_refs"]) if f.cve_refs else ""
        writer.writerow([
            f.severity, f.category, f.title, f.description, f.evidence, f.recommendation, cve_refs,
        ])

    buffer.seek(0)
    return buffer.getvalue()
