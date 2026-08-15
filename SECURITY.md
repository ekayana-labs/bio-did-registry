# Security Policy

## Reporting security problems

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Instead please use the
[Report a Vulnerability](https://github.com/ekayana-labs/did-bio-registry/security/advisories/new)
link. Provide a helpful title and a detailed description of the problem.

If you haven't done so already, please **enable two-factor auth** in your
GitHub account.

Expect a response in the advisory as fast as possible, typically within 72
hours.

--

If you do not receive a response in the advisory, send an email to
<suraj410401@gmail.com> with the full URL of the advisory you have created.
Do not include attachments or provide detail sufficient for exploitation
regarding the security issue in this email. **Only provide such details in
the advisory**.

## Scope

The `did-bio-registry` program at
[program](https://github.com/ekayana-labs/did-bio-registry/tree/main/program)
is in scope: anything that lets a non-authority mutate a DID document,
resurrect a deactivated DID, orphan a DID of its last update authority,
corrupt the account layout, or drain lamports from a registry account.

If you discover an issue in an out of scope component (clients, resolver,
specification), your finding is still valuable - please report it through
the same channel.
