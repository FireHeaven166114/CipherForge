# Infrastructure as code

**Status: not implemented.** This directory is a placeholder for the Azure deployment planned in
roadmap phase 11. There are no templates here, and no Azure resources are created by this repository.

## Planned scope

Bicep or Terraform (not yet chosen) describing:

- container hosting (Azure Container Apps or App Service) for the API and the web app;
- Azure Database for PostgreSQL;
- Blob Storage for encrypted files (only once Vault exists);
- Key Vault for server-side secrets, accessed through managed identities;
- Microsoft Entra ID for sign-in and app roles;
- Azure Monitor and Application Insights for telemetry.

The exit criterion from the specification is that the deployment is reproducible and no secrets are
embedded in it.

For running the project today, see [../docs/deployment.md](../docs/deployment.md), which also records
what has and has not been verified.
