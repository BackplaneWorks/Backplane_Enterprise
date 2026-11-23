# Backplane Enterprise

Open-source (MIT), self-hostable and AWS-managed enterprise control plane for [Backplane](https://github.com/BackplaneWorks/Backplane) hardware and firmware teams.

## What's Inside

- **Zero-Tailscale Managed Boat VMs:** Preloaded with Backplane + `Backplane_KiCad`, controlled seamlessly from your local desktop app over outbound mTLS/WSS relay (no VPN or inbound firewall rules).
- **Private KiCad HTTP Library & Web Librarian:** Tenant-isolated `kicad_httplib` server, parametric lifecycle management (`Draft → Released → Obsolete`), where-used tracking, web symbol/footprint editing, and 1-click "Open in KiCad".
- **Web Co-Development & Purchasing Portal:** Role-based web UI (OAuth/SSO) for board/schematic/3D reviews, ECOs, live BOM/stock/alternates, and purchasing approvals without needing KiCad locally.
- **Admin Governance:** RBAC, LLM provider/model allowlists, optional ZDR enforcement, approval gates, and tamper-evident audit logs.
- **Encrypted Ordering & Email Integration:** Google Workspace (Gmail) + Microsoft 365 (Outlook) connectors, KMS envelope-encrypted order & email database, automated status tracking, and Stripe billing.
- **AWS + Self-Host Ready:** Terraform modules for AWS (`infra/terraform/aws`), Helm chart (`infra/helm`), and 1-command `docker compose` (`infra/docker`).

See [docs/SPEC.md](docs/SPEC.md) for the full architecture and [docs/SECURITY.md](docs/SECURITY.md) for the cybersecurity review and threat model.

## License

MIT — see [LICENSE](LICENSE).
