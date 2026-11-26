# Infrastructure as code

**Status: not implemented.** This directory is a placeholder for the Azure deployment planned in
roadmap phase 11 (phases 5 to 12 have not been started, see
[project-status.md](../docs/project-status.md#not-implemented-yet)). There are no templates here, and
no Azure resources are created by this repository.

## Planned scope

Bicep or Terraform (not yet chosen) describing:

- container hosting (Azure Container Apps or App Service) for the API and the web app;
- Azure Database for PostgreSQL;
- Blob Storage for encrypted files. The file-sharing module exists and keeps its encrypted blobs on
  the local disk of the API host today (see [../docs/file-sharing.md](../docs/file-sharing.md));
  moving them to Blob Storage is planned and not built;
- Key Vault for server-side secrets, accessed through managed identities. Provider API keys and the
  file-sharing master key are read from environment variables today;
- Microsoft Entra ID for sign-in and app roles. The API already validates Entra ID tokens when
  `AUTH_MODE=entra` (set up by hand, see
  [deployment.md](../docs/deployment.md#entra-id-setup-for-auth_modeentra)); the dashboard has no
  sign-in flow yet, and nothing in this directory creates the app registration;
- Azure Monitor and Application Insights for telemetry.

The exit criterion from the specification is that the deployment is reproducible and no secrets are
embedded in it.

For running the project today, see [../docs/deployment.md](../docs/deployment.md), which also records
what has and has not been verified.
