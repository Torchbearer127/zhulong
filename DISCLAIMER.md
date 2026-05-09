# Disclaimer

Zhulong is a security-focused code audit workflow for authorized use only. This
project is provided only for academic research, teaching, and learning in
cyberspace security. This disclaimer is intended to make the project's safety
boundaries explicit for users, contributors, maintainers, and downstream
redistributors.

## Authorized Use Only

Use Zhulong only for legitimate cyberspace-security academic research,
teaching, and learning, and only on codebases, systems, containers, services,
accounts, networks, and infrastructure that you own or are explicitly
authorized to test.

You are responsible for complying with applicable laws, contracts, program
rules, disclosure policies, and organizational security requirements.

Zhulong does not grant you permission to test, scan, access, exploit, disrupt,
or assess any third-party target. If your authorization is unclear, do not use
Zhulong on that target.

## No Illegal Or Harmful Use

Do not use Zhulong or its generated artifacts for:

- unauthorized vulnerability testing
- unauthorized penetration testing
- scanning or probing third-party systems without permission
- exploitation against systems without permission
- credential theft or secret exfiltration
- persistence, lateral movement, disruption, or denial of service
- evading monitoring, policy, or access controls
- developing, improving, or operationalizing malware or harmful tooling
- publishing exploitable details before an affected project has had reasonable
  time to triage and remediate

## Tool Output Is Not Final Judgment

Zhulong is designed to reduce false-positive burden by separating confirmed
findings, candidates, false positives, blocked items, and unverified leads.

Even so, generated output requires human review before remediation,
publication, disclosure, or operational use. A confirmed bundle is an evidence
package, not legal advice, compliance advice, or a substitute for expert
security judgment.

Do not submit, publish, or operationalize a generated finding until a qualified
human reviewer has checked scope, authorization, reproduction evidence,
attacker conditions, server conditions, and security impact.

## Agent And Provider Policy Compliance

Zhulong is designed to run through local agent workflows and helper scripts. The
agent runtime, model provider, IDE, hosting platform, or API you choose may have
its own usage policies, safety rules, privacy terms, retention rules, and rate
limits.

You are solely responsible for reading and following those policies, including
policies from tools such as Claude Code, Codex, Cursor, Gemini CLI, model
providers, code hosts, bug bounty platforms, and organizational security
programs. Zhulong does not override those policies and must not be used to
bypass an agent, model provider, platform, or program's safety controls.

## Responsible Disclosure

If Zhulong helps identify a vulnerability in a third-party project, follow the
affected project's official security policy or maintainer-designated private
reporting channel. Do not disclose exploitable details publicly before the
affected project has had reasonable time to triage and remediate.

Security issues in Zhulong itself should be reported according to
[SECURITY.md](SECURITY.md).

## Privacy And Confidentiality

Zhulong does not require a hosted backend, dashboard, database, vector store, or
RAG service. Its normal artifacts are local.

The AI coding agent and model/provider you use may process repository content
according to their own configuration and policies. Review those policies before
auditing private, confidential, regulated, or third-party code.

Do not process code that you are not permitted to share with your chosen agent,
model provider, local runtime, or collaborators. You are responsible for
removing secrets, personal data, regulated data, proprietary information, and
other sensitive material when required by law, contract, or policy.

## Assumption Of Risk And Limitation Of Liability

Zhulong is provided under the MIT License. It is provided "as is", without
warranty of any kind, express or implied.

To the maximum extent permitted by applicable law, the authors, maintainers,
contributors, and copyright holders are not liable for any direct, indirect,
incidental, special, consequential, exemplary, punitive, legal, regulatory,
commercial, operational, or data-related damages, losses, claims, disputes, or
liabilities arising from use, misuse, modification, redistribution, or reliance
on Zhulong or its generated artifacts.

You use Zhulong at your own risk. You are solely responsible for all legal,
compliance, operational, security, disclosure, data-handling, and financial
consequences of your use.

See also:

- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE)
