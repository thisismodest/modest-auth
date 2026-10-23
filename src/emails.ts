// An email address, made the one form it's kept in, or refused.
//
// - Length is checked first, before anything else is done with it, and the rest is
//   plain string checks: no pattern that a crafted address can make slow.
// - Unicode is normalised (NFKC), so lookalike forms ("ａｎｎ" and "ann") are one
//   address, not two accounts; and the domain is kept in its ASCII form (as the
//   URL standard gives it), so "bücher.de" and "xn--bcher-kva.de" are one too.
// - Invisible and control characters (bidirectional overrides among them, which can
//   make an address display as another) are refused, as are spaces, quotes, and
//   brackets: an app that shows an email can't be handed markup through one. So is a
//   leading "-" or "|", which a mail program could take as an option or a pipe.

/** RFC 5321's limits: 254 in all, 64 before the @. */
const LONGEST = 254;
const LONGEST_LOCAL = 64;
// Control, format, and unassigned characters, separators, and anything Unicode says is drawn as nothing
// (variation selectors, fillers), plus the blank braille cell; and characters that mean something in markup.
const FORBIDDEN = /[\p{C}\p{Z}\p{Default_Ignorable_Code_Point}\u2800\s"'<>()[\]\\,;:`]/u;

/** The address as it's kept (trimmed, normalised, lowercase), or null if it isn't one. */
export function cleanEmail(given: string): string | null {
  if (typeof given !== "string" || given.length > LONGEST * 4) return null;
  const email = given.trim().normalize("NFKC").toLowerCase();
  if (email.length > LONGEST || FORBIDDEN.test(email)) return null;
  const at = email.indexOf("@");
  if (at < 1 || at !== email.lastIndexOf("@") || at > LONGEST_LOCAL) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  // Nor one a mail program would read as a command-line option or a pipe ("-X/file@x.org", "|cmd@x.org"), should an app pass it to one.
  if (local.startsWith("-") || local.startsWith("|")) return null;
  // Nothing a URL would read as more than a host (a path, query, fragment, or %-escape), before the URL parser sees it.
  if (/[/?#%]/.test(domain)) return null;
  let ascii: string;
  try {
    ascii = new URL(`http://${domain}`).hostname;
  } catch {
    return null;
  }
  const labels = ascii.split(".");
  if (labels.length < 2 || labels.some((label) => label.length === 0 || label.length > 63 || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9_-]+$/.test(label))) return null;
  // A name, not a number: the last label has a letter, so an IP address (in any of its spellings) isn't a domain here.
  if (!/[a-z]/.test(labels.at(-1)!)) return null;
  const kept = `${local}@${ascii}`;
  return kept.length <= LONGEST ? kept : null;
}
