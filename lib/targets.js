/**
 * SecureLoop - Audit Target Helpers
 *
 * Keeps the original OpenClaw skill lookup intact while allowing SecureLoop to
 * audit broader local targets such as a project folder or the local machine.
 */

import fs from "fs";
import os from "os";
import path from "path";
import { resolveSkillPath } from "./resolveSkill.js";

export function resolveAuditTarget(targetName = "system") {
  const raw = String(targetName || "system").trim();
  const lower = raw.toLowerCase();

  if (["system", "pc", "computer", "machine", "device", "localhost"].includes(lower)) {
    return {
      name: raw,
      type: "system",
      root: os.homedir(),
      display: "Local machine",
    };
  }

  const expanded = raw.startsWith("~/")
    ? path.join(os.homedir(), raw.slice(2))
    : raw;
  const absolute = path.resolve(expanded);
  if (fs.existsSync(absolute) && fs.statSync(absolute).isDirectory()) {
    return {
      name: raw,
      type: "path",
      root: absolute,
      display: absolute,
    };
  }

  const skillPath = resolveSkillPath(raw);
  if (skillPath) {
    return {
      name: raw,
      type: "skill",
      root: skillPath,
      display: skillPath,
    };
  }

  return {
    name: raw,
    type: "missing",
    root: null,
    display: raw,
  };
}

export function targetLabel(targetName) {
  const target = resolveAuditTarget(targetName);
  if (target.type === "system") return "local machine";
  if (target.type === "path") return target.display;
  return target.name;
}
