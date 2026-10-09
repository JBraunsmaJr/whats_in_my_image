# Reports

Every scan writes its results to `./wimi-reports/` (change with `-o DIR`). The file names use the last part of the
image reference, so `registry.example.mil/team/api:2.4` becomes `provenance-api_2.4.*`.

| File | For |
| --- | --- |
| `provenance-<image>.html` | **Executive report.** One self-contained file to email, attach to a ticket, or print to PDF. |
| `provenance-<image>.json` | Full data for automation and dashboards. |
| `provenance-<image>-components.csv` | Inventory for spreadsheets: supplier, layer, evidence and concerns for every component. |
| `provenance-<image>-vulnerabilities.csv` | Every CVE with the party that introduced it. Written only when vulnerability data was supplied. |

Choose which formats to write with `--formats` (default `html,json,csv`), and add a line above the report heading
with `--subtitle "Prepared for CISO review"`. Use `-q` to print only the final summary.

[See a sample report](../sample-report.html){ .md-button .md-button--primary }

<div class="grid cards" markdown>

-   :material-file-document-outline:{ .lg .middle } **[The HTML report](html-report.md)**

    ---

    What each section of the executive report shows, and who it's for.

-   :material-table:{ .lg .middle } **[JSON and CSV](data-exports.md)**

    ---

    Columns and fields for spreadsheets, dashboards and automation.

</div>
