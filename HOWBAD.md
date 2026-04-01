# How Bad Is This?

Genuinely one of the worst npm supply chain attacks in history. Here's why:

**Scale is staggering.** axios isn't some niche library — it's the HTTP client for JavaScript. 100M weekly downloads, 174K direct dependents, present in ~80% of cloud environments. It's in the dependency tree of VS Code, Slack, Discord, Postman, and practically every enterprise Node.js app. This is like poisoning the water supply.

**The attack window was tiny but devastating.** Only ~3 hours (00:21–03:29 UTC). But that's overnight in the US, which means automated CI/CD pipelines — nightly builds, canary deploys, staging refreshes — were running `npm install` unattended. Huntress confirmed 135 endpoints contacted C2 during just that window. The real number is unknown.

**15 seconds from install to full compromise.** The dropper executes during `npm install`, fetches the RAT, installs persistence, and cleans up after itself. By the time the install finishes, the machine is owned. Most developers wouldn't notice anything.

**The self-cleaning dropper is nasty.** It deletes `setup.js`, replaces the malicious `package.json` with a clean copy. Post-incident forensics on `node_modules` reveals nothing. If you didn't capture the state during the install, the evidence is gone. This is why our scanner checks multiple layers (lockfiles, registry, host artifacts) — you can't rely on just one.

**DPRK state actor.** This isn't a teenager defacing websites. UNC1069 is a professional threat group linked to North Korea's cyber operations. They've done this before (WAVESHAPER backdoor overlap). The RAT supports in-memory DLL injection, arbitrary command execution, and directory enumeration. This is espionage/theft infrastructure.

**The broader pattern is terrifying.** SANS noted a possible link to the TeamPCP cascading supply chain campaign targeting Trivy, KICS, and LiteLLM in the preceding two weeks. If that connection holds, this is part of a coordinated campaign to compromise the entire JS/Python security tooling ecosystem.

## What It Means for IT

- **Lockfiles are no longer optional.** Any project running `npm install` without a pinned lockfile during that window may have been compromised.
- **npm account security is critical infrastructure.** One maintainer account compromise = 100M machines at risk. npm still doesn't enforce hardware 2FA for high-impact packages.
- **CI/CD pipelines are the real attack surface.** Developers rebuild rarely. CI rebuilds constantly. Overnight builds with `npm install` are the primary infection vector.
- **Post-breach trust is zero.** If a machine ran `npm install` during the window, every credential on that machine should be rotated. Every SSH key, every API token, every cloud credential. The RAT had 60-second beacons — anything accessible was exfiltrated.

This is the `event-stream` attack at 1000x scale with a nation-state behind it.
