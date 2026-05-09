# Security Policy

## Supported Versions

Zhulong is currently a release-candidate project. Security fixes should target
the latest public release candidate unless a maintainer states otherwise.

## Responsible Use

Zhulong is intended for authorized code review, internal security assessment,
responsible vulnerability research, and academic research, teaching, and
learning in cyberspace security.

Do not use Zhulong against repositories, systems, services, accounts, networks,
or infrastructure where you do not have permission to test.

Use of Zhulong must comply with applicable laws, contracts, security program
rules, and organizational policies. The project does not grant permission to
test any third-party target.

Do not use Zhulong or generated artifacts for unauthorized exploitation,
credential theft, persistence, lateral movement, denial of service, policy
evasion, or data exfiltration.

Do not use Zhulong to bypass safety controls, terms of service, acceptable-use
policies, disclosure rules, or rate limits imposed by your agent runtime, model
provider, IDE, code host, bug bounty platform, employer, or customer.

If authorization, scope, or data-handling permission is uncertain, stop and
obtain written approval before using Zhulong.

## Agent And Provider Policy Compliance

Zhulong does not require a hosted backend, dashboard, database, vector store, or
RAG service, but it is normally operated through a local coding agent and the
model/provider configuration selected by the user.

Users are responsible for complying with the policies of the tools and services
they choose, including local agent runtimes, model providers, code hosts,
container registries, vulnerability disclosure programs, and organizational
security policies. Zhulong does not override or replace those policies.

## Reporting A Security Issue In Zhulong

If you find a security issue in Zhulong itself, please report it privately first:

- Email: [torchbearer127@qq.com](mailto:torchbearer127@qq.com)
- GitHub: [@Torchbearer127](https://github.com/Torchbearer127)

Please include:

- affected version or commit
- affected component or file path
- impact summary
- reproduction steps or proof-of-concept details
- whether Docker, agent runtime, or generated audit artifacts are involved

Do not include unrelated target-project vulnerabilities in a Zhulong product
security report. Report those to the affected upstream project through its own
security policy.

## Reporting Vulnerabilities Found With Zhulong

Zhulong can help produce confirmed evidence bundles, but users remain
responsible for disclosure decisions.

When reporting vulnerabilities discovered during an audit:

- follow the target project's `SECURITY.md` or official security policy
- disclose only through authorized channels
- avoid public disclosure until the affected project has had reasonable time to
  triage and fix the issue
- do not use confirmed findings for unauthorized access, persistence,
  exfiltration, disruption, or lateral movement
- avoid attaching unrelated private code, credentials, user data, or excessive
  logs to upstream reports
- clearly distinguish Docker-reproduced evidence from candidates, blocked
  verification, or unverified leads

## Data Handling Reminder

Zhulong does not require a hosted backend, dashboard, database, vector store, or
RAG service. Audit artifacts are normally written under the target repository's
local audit workspace.

However, the active AI coding agent and model/provider configuration may still
determine what repository content is read or sent to a model provider. Review
your local agent and provider policies before auditing private code.

Do not use Zhulong on private, confidential, regulated, customer-owned, or
third-party code unless you are allowed to process that code with your selected
agent, model provider, runtime environment, collaborators, and storage
location. Remove or redact secrets, personal data, regulated data, credentials,
tokens, and unnecessary logs where required.

## No Warranty

Security tooling can produce false positives, false negatives, and incomplete
evidence. Zhulong preserves evidence and enforces confirmed-only gates, but it
does not replace expert review, legal judgment, or responsible disclosure
processes.

Use of Zhulong is at the user's own risk. To the maximum extent permitted by
applicable law, the authors, maintainers, contributors, and copyright holders
are not responsible for legal, compliance, operational, financial, security, or
data-handling consequences arising from use or misuse.

See also [DISCLAIMER.md](DISCLAIMER.md).
