"""
Generate a small Sec+-themed PDF fixture for /ingest/file stress testing.

Run via one-shot Python container (fpdf2 not in main requirements.txt because
it's a test-only dep):

    docker run --rm -v ~/Desktop/Tech-Projects/rag-api:/work \
        python:3.11-slim sh -c "pip install fpdf2 -q && python /work/tests/make_fixture_pdf.py"

Output: tests/fixtures/secplus-fixture.pdf  (gitignored)

The text is intentionally multi-paragraph and ~2KB so the recursive splitter
produces multiple chunks (proves chunk_index increments correctly).
"""

from pathlib import Path

from fpdf import FPDF

SECPLUS_TEXT = """\
CompTIA Security Plus Study Notes (Test Fixture)

Domain 1: Threats, Attacks, and Vulnerabilities

Phishing is a social engineering attack in which adversaries impersonate \
trusted entities to harvest credentials or deliver malware. Spear phishing \
targets specific individuals; whaling targets executives. Defense relies on \
user training, email gateway filtering, and DMARC/DKIM/SPF authentication.

Domain 2: Architecture and Design

Defense in depth layers multiple controls so that the failure of any single \
control does not result in compromise. Examples include perimeter firewalls, \
network segmentation, host-based intrusion prevention, application allowlisting, \
and least-privilege user accounts. The principle of least privilege grants \
each subject only the permissions strictly required for its task.

Domain 3: Implementation

Public Key Infrastructure (PKI) uses asymmetric cryptography to bind public \
keys to identities through digital certificates issued by Certificate \
Authorities. TLS uses PKI for server authentication and key agreement. \
Certificate revocation is handled via CRLs (Certificate Revocation Lists) \
or OCSP (Online Certificate Status Protocol).

Domain 4: Operations and Incident Response

The incident response lifecycle has six phases: preparation, identification, \
containment, eradication, recovery, and lessons learned. Containment is \
divided into short-term (isolate the affected system) and long-term \
(harden the environment for safe restoration of operations).

Domain 5: Governance, Risk, and Compliance

Risk management balances likelihood and impact. Quantitative risk uses \
Single Loss Expectancy (SLE) and Annualized Loss Expectancy (ALE = SLE x ARO). \
Qualitative risk uses high/medium/low rankings. Risk treatment options: \
accept, avoid, mitigate, or transfer.
"""


def main() -> None:
    out_dir = Path(__file__).parent / "fixtures"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "secplus-fixture.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(w=0, h=6, text=SECPLUS_TEXT)
    pdf.output(str(out_path))

    size_kb = out_path.stat().st_size / 1024
    print(f"Wrote {out_path} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
