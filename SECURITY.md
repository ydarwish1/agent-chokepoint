# Security Policy

How to report a security defect **in Agent-Chokepoint itself**.

## Reporting

Use GitHub's [private vulnerability reporting](https://github.com/ydarwish1/agent-chokepoint/security/advisories/new) on this repository. If that is unavailable to you, reach the maintainer at `182555523+ydarwish1@users.noreply.github.com`.

**Please do not open a public issue for an exploitable bug.** That publishes it before there is a fix.

Send what you did, what happened, and what you expected instead. A payload plus the command that runs it beats a description of one.

## What to expect

**Acknowledgment within 7 days, best effort.** Read that as a commitment rather than a measurement. This is a one-person project with no rotation and no on-call, and that bound is the honest one. There is no severity table and no per-severity response time here, because nothing has measured them and a placeholder number in a security policy is a lie with a footnote.

## Supported versions

There is no supported-versions table yet. The package version is `0.0.1.dev0`, there are no releases and no tags, and `main` is the only line there is to fix.

## Before you report a bypass

This project publishes no effectiveness numbers: no bypass rate, no false-block rate. `docs/LIMITATIONS.md` is the written account of what this gateway does not stop, class by class, with the measurement beside each entry, and the README's *A note on numbers* section explains why there are no figures. Both are worth reading first — what you found may already be in there, named and bounded, in which case a report that sharpens the entry is still welcome.
