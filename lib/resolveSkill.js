/**
 * SecureLoop - Skill Path Resolver
 * by Jorge Elizalde
 *
 * Single source of truth for locating an installed skill on disk.
 * Order matches CLAUDE.md and TECHNICAL_CONTEXT.md SKILL PATH RESOLVER spec.
 *
 * Used by all 3 scanner modules so they can never drift.
 */

import fs from "fs";
import os from "os";
import path from "path";

/**
 * Returns the first existing directory for the given skill name,
 * or null if not found. Follows the priority order documented in CLAUDE.md.
 *
 * @param {string} skillName
 * @returns {string | null}
 */
export function resolveSkillPath(skillName) {
  const home = os.homedir();
  const cwd  = process.cwd();

  const candidates = [
    path.join(home, ".openclaw", "extensions", skillName), // priority_1 — PRIMARY on macOS
    path.join(home, ".openclaw", "skills",     skillName), // priority_2
    path.join(home, ".openclaw", "plugins",    skillName), // priority_3
    path.join(home, ".openclaw",               skillName), // priority_4
    path.join(cwd,  "skills",                  skillName), // priority_5
    path.join(cwd,  "plugins",                 skillName), // priority_6
    path.join(home, "Desktop",                 skillName), // priority_7
  ];

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
        return candidate;
      }
    } catch {
      // ignore permission errors on any candidate and keep searching
    }
  }

  return null;
}

// Default export for convenience (some imports prefer default).
export default resolveSkillPath;
