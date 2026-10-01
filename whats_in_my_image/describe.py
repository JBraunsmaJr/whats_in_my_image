"""Translate raw Dockerfile build steps into plain English and flag risky practices."""

from __future__ import annotations

import re

_RULES: list[tuple[str, str]] = [
    (
        r"\b(dnf|yum|microdnf|tdnf)\b[^;&|]*\b(update|upgrade|distro-sync)\b",
        "Updated operating-system packages to newer versions",
    ),
    (r"\b(dnf|yum|microdnf|tdnf)\b[^;&|]*\b(install|reinstall)\b", "Installed operating-system packages (dnf/yum)"),
    (r"\brpm\b\s+(-[a-zA-Z]*[iU]|--install|--upgrade)", "Installed RPM package files directly (rpm)"),
    (r"\b(apt-get|apt)\b[^;&|]*\b(upgrade|dist-upgrade)\b", "Updated operating-system packages to newer versions"),
    (r"\b(apt-get|apt)\b[^;&|]*\binstall\b", "Installed operating-system packages (apt)"),
    (r"\bdpkg\s+-i\b", "Installed .deb package files directly (dpkg)"),
    (r"\bapk\b[^;&|]*\bupgrade\b", "Updated operating-system packages to newer versions"),
    (r"\bapk\b[^;&|]*\badd\b", "Installed operating-system packages (apk)"),
    (r"\b(pip3?|python3?\s+-m\s+pip|pipenv|poetry|uv)\b[^;&|]*\b(install|sync)\b", "Installed Python libraries"),
    (r"\b(npm|yarn|pnpm)\b[^;&|]*\b(install|ci|add)\b|\byarn\s*($|&&|;)", "Installed JavaScript (Node.js) libraries"),
    (r"\b(mvn|mvnw|gradle|gradlew)\b", "Built a Java application (Maven/Gradle)"),
    (r"\bgo\s+(build|install)\b", "Compiled a Go program"),
    (r"\bcargo\s+(build|install)\b", "Compiled a Rust program"),
    (r"\b(make|cmake|gcc|g\+\+|configure)\b", "Compiled software from source code"),
    (r"\b(gem|bundle)\s+install\b", "Installed Ruby libraries"),
    (r"\b(curl|wget)\b", "Downloaded files from the internet"),
    (r"\bgit\s+clone\b", "Cloned source code from a Git repository"),
    (r"\b(tar|unzip|gunzip)\b", "Unpacked an archive"),
    (r"\b(useradd|adduser|groupadd|addgroup|usermod)\b", "Created or changed user accounts"),
    (r"\b(chmod|chown|chgrp|setcap)\b", "Changed file ownership or permissions"),
    (r"\b(update-ca-trust|update-ca-certificates)\b", "Updated trusted certificate authorities"),
    (r"\b(rm|clean\s+all)\b", "Removed files / cleaned caches"),
    (r"\b(sed|echo|cat|tee|printf|ln)\b", "Edited or created configuration files"),
]

_RISKS: list[tuple[str, str, str]] = [
    (
        r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b",
        "high",
        "Downloads a script from the internet and runs it immediately (no verification)",
    ),
    (
        r"--nogpgcheck|gpgcheck\s*=\s*0|--no-gpg-checks|--allow-unauthenticated|AllowUnauthenticated|--allow-untrusted",
        "high",
        "Package signature checking was turned off",
    ),
    (
        r"\bcurl\b[^;&|]*\s(-k|--insecure)\b|wget[^;&|]*--no-check-certificate|sslverify\s*=\s*(0|false)|strict-ssl\s+false",
        "high",
        "TLS certificate checking was turned off for a download",
    ),
    (r"--trusted-host", "medium", "Python packages were fetched from a host with TLS checks disabled"),
    (
        r"--extra-index-url|--index-url|-i\s+https?://",
        "medium",
        "Python packages were pulled from a non-default package index",
    ),
    (r"\bchmod\b[^;&|]*\b(0?777|a\+rwx|o\+w)\b", "medium", "Files were made writable by every user (chmod 777)"),
    (
        r"\b(curl|wget)\b|\bADD\s+https?://",
        "medium",
        "Content was downloaded directly from the internet, bypassing vendor-signed packages",
    ),
    (
        r"\bsetcap\b|\bchmod\b[^;&|]*\b[ug]\+s\b|\bchmod\b[^;&|]*\b[2467][0-7]{3}\b",
        "low",
        "Elevated privileges (setuid / capabilities) were granted to a program",
    ),
]

METADATA_INSTRUCTIONS = {
    "LABEL",
    "ENV",
    "CMD",
    "ENTRYPOINT",
    "EXPOSE",
    "ARG",
    "VOLUME",
    "SHELL",
    "HEALTHCHECK",
    "ONBUILD",
    "STOPSIGNAL",
    "USER",
    "WORKDIR",
    "MAINTAINER",
}
URL_RE = re.compile(r"https?://[^\s'\"\\;|&)]+")


def clean_command(created_by: str) -> tuple[str, str]:
    """Return (instruction, body) e.g. ('RUN', 'dnf install -y python3')."""
    s = (created_by or "").strip()
    s = re.sub(r"\s*# buildkit\s*$", "", s)
    s = re.sub(r"^\|\d+(\s+\S+=\S*)*\s+", "", s)  # buildkit ARG prefix
    m = re.match(r"^(/bin/(ba)?sh|sh)\s+-c\s+(.*)$", s, re.S)
    if m:
        s = m.group(3).strip()
        n = re.match(r"^#\(nop\)\s*(.*)$", s, re.S)
        if n:
            s = n.group(1).strip()
            ins, _, body = s.partition(" ")
            return ins.upper(), body.strip()
        return "RUN", s
    ins, _, body = s.partition(" ")
    if ins.upper() in (
        "RUN",
        "COPY",
        "ADD",
        "WORKDIR",
        "ENV",
        "USER",
        "LABEL",
        "CMD",
        "ENTRYPOINT",
        "EXPOSE",
        "ARG",
        "VOLUME",
        "SHELL",
        "HEALTHCHECK",
        "ONBUILD",
        "STOPSIGNAL",
    ):
        return ins.upper(), body.strip()
    return ("RUN" if s else ""), s


def describe(created_by: str, comment: str = "") -> dict:
    """Plain-English description of one build step plus any risk findings."""
    ins, body = clean_command(created_by)
    actions: list[str] = []
    if not ins:
        if comment:
            actions.append(f"Build tool note: {comment}")
        else:
            actions.append("No build record was kept for this layer (typical of a base OS filesystem)")
    elif ins in ("COPY", "ADD"):
        body_wo_flags = re.sub(r"--(chown|chmod|link|parents|exclude)(=\S+)?\s*", "", body)
        frm = re.search(r"--from=(\S+)", body_wo_flags)
        dest = body_wo_flags.split()[-1] if body_wo_flags.split() else ""
        if ins == "ADD" and URL_RE.search(body):
            actions.append(f"Downloaded a file from the internet into {dest}")
        elif frm:
            actions.append(f"Copied build output from an earlier build stage ('{frm.group(1)}') into {dest}")
        else:
            actions.append(
                f"Copied files from the build workspace into {dest}" if dest else "Copied files into the image"
            )
    elif ins == "RUN" and body.startswith("#"):
        actions.append("Root filesystem created by the image publisher's build tooling")
    elif ins == "RUN":
        for pattern, text in _RULES:
            if re.search(pattern, body) and text not in actions:
                actions.append(text)
        if not actions:
            actions.append("Ran a build command")
    else:
        actions.append(f"{ins} instruction")
    risks = []
    text = f"{ins} {body}"
    seen = set()
    for pattern, sev, msg in _RISKS:
        if re.search(pattern, text, re.I) and msg not in seen:
            if msg.startswith("Content was downloaded") and any(
                r["message"].startswith("Downloads a script") for r in risks
            ):
                continue
            seen.add(msg)
            risks.append({"severity": sev, "message": msg})
    return {
        "instruction": ins,
        "command": body,
        "summary": "; ".join(actions[:4]),
        "actions": actions,
        "urls": sorted(set(URL_RE.findall(body)))[:20],
        "risks": risks,
    }
