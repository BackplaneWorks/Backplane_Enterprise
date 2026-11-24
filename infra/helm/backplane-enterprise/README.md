# Backplane Enterprise Helm Chart

Deploy Backplane Enterprise into any Kubernetes cluster (EKS, GKE, AKS, or on-prem k3s/OpenShift).

## Security Highlights

- **Split DB Credentials:** `migrate` Job uses a dedicated `ServiceAccount` (`*-migrate`) and mounts `databaseAdminUrl` (`DATABASE_ADMIN_URL`). `api` and `relay` use separate `ServiceAccount`s (`*-runtime`) and mount ONLY `databaseAppUrl` (`DATABASE_URL`, connecting as `bp_app` with `NOBYPASSRLS`).
- **Non-Root Containers:** All pods run with `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ["ALL"]`.
- **NetworkPolicies:** Default-deny ingress with explicit allowlists between `ingress -> web -> {api, relay}` and `relay:8443` mTLS from Boat VMs.
- **Strict CSP/HSTS:** Enforced at the Ingress and nginx layers with zero `unsafe-inline` scripts.
- **Stripe Boat VM Metering:** Configure `billing.stripeVmPriceId` as a metered price on a meter matching `billing.stripeVmMeterEvent` (`boat_vm_minutes`) with `transform_quantity[divide_by]=60` for hourly pricing (whole minutes are reported per VM run).
