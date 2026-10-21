# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub instead: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the steps to reproduce, the affected version or commit, and the impact you expect.

You should get a first reply within 7 days. Once a fix is ready, the report will be published as a GitHub security advisory, with credit to you unless you prefer otherwise.

## Supported versions

Only the latest commit on `main` receives security fixes.

## Scope

In scope: the API, the worker, the web app, the Docker setup, and the CI workflows in this repository.

Out of scope: vulnerabilities in the tools VulnCompass runs (Semgrep, Trivy, OWASP ZAP) should be reported to those projects. Findings that VulnCompass reports about *other* projects are not vulnerabilities in VulnCompass.

## Safe use

VulnCompass makes the server scan folders and web applications. Run it only against targets you are allowed to test, keep `SCAN_ALLOWED_REPO_ROOTS` and `SCAN_ALLOWED_HOSTS` as narrow as possible, and do not expose the web app to the public internet.
