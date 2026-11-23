# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" button on this
repository (Security tab), not in public issues. Include the affected endpoint or component, steps to
reproduce and the impact you expect.

- We acknowledge reports within 3 working days.
- We aim to confirm and give a fix timeline within 10 working days.
- We credit reporters in the release notes unless they ask us not to.

This policy follows ETSI EN 303 645 provision 5.2.

## Supported versions

Only the latest commit on `main` receives security fixes.

## Deployment requirements

- Run behind TLS; HSTS is sent outside Development.
- Set `HavenHub__MasterKey` and `HavenHub__TokenKey` to base64 random 256-bit keys (e.g.
  `openssl rand -base64 32`). The service refuses to start without them outside Development.
- Keep the master key out of the database host's backups.
