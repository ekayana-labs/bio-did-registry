# Security Policy

## Reporting security problems

Do not open a GitHub issue to report a security problem.

Please use the
[Report a Vulnerability](https://github.com/ekayana-labs/bio-did-registry/security/advisories/new)
link with a helpful title and a detailed description of the problem.

If you have not done so already, please enable two-factor auth in your
GitHub account.

Expect a response in the advisory as fast as possible, typically within 72
hours.

If you receive no response in the advisory, email <suraj410401@gmail.com>
with the full URL of the advisory you have created. Keep attachments and
exploit details in the advisory and out of the email.

## Scope

The `bio-did-registry` program in
[program](https://github.com/ekayana-labs/bio-did-registry/tree/main/program)
is in scope. That covers anything that lets a non-authority mutate a DID
document, resurrect a deactivated DID, orphan a DID of its last update
authority, corrupt the account layout, or drain lamports from a registry
account.

The clients, the resolver and the specification are out of scope here, but
a finding in one of them is still valuable. Please report it through the
same channel.
