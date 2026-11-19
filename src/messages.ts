// What modest-auth asks the app to send, as data: what it's for, who it's to,
// and the link in it, if any. The app delivers it however it likes (an email
// service, a text message, in its own words or language). emailFor writes
// modest-auth's own plain-text email for one, for apps that don't want to.

import type { Contact, Link } from "./auth.ts";
import { isPlainLine } from "./text.ts";
import { MINUTE } from "./time.ts";

/**
 * Something to send to someone, after the answer to whoever asked has gone. `link` signs in, makes an account,
 * or changes it, so it goes only to `to`: never into a log, an analytics tool, or a link-tracking service, and
 * never back to whoever asked. It stops working at `expires`.
 */
export type Message =
  /** A link that makes an account at an address that has none: to choose a password, or (on a site without passwords) to sign in. */
  | { kind: "sign-up"; to: Contact; link: string; expires: number }
  /** A link that signs in. */
  | { kind: "sign-in"; to: Contact; link: string; expires: number }
  /** A link to choose a new password, for an account that has forgotten it (or lost it, by an undone move). */
  | { kind: "new-password"; to: Contact; link: string; expires: number }
  /** A sign-in link was asked for an address with no account, on a site where accounts are made by choosing a password. */
  | { kind: "no-account"; to: Contact }
  /** A sign-in link was asked for an account that signs in by passkey only, where only the site can send a way back in. */
  | { kind: "passkey-only"; to: Contact }
  /** A link that moves an account to this, its new address, opened where the account is signed in. */
  | { kind: "confirm-email"; to: Contact; link: string; expires: number }
  /** An account asked to move to this address, which has an account of its own: nothing changed. */
  | { kind: "email-in-use"; to: Contact }
  /** The account's password was just changed, and every other session ended. */
  | { kind: "password-changed"; to: Contact }
  /** The account was just deleted, with everything kept about it. */
  | { kind: "account-deleted"; to: Contact }
  /** To the address an account just moved from: it moved to `email`, and `link` undoes it. */
  | { kind: "email-changed"; to: Contact; email: string; link: string; expires: number }
  /** A passkey, named `name`, was just added to the account. */
  | { kind: "passkey-added"; to: Contact; name: string }
  /** A passkey, named `name`, was just removed from the account. */
  | { kind: "passkey-removed"; to: Contact; name: string };

/**
 * The message for a link that `requestLink`, `requestEmailChange`, or `useUndoLink` (its `reset`) gave: what it's
 * for, from its kind and whether it can be opened, with `url`, the page it opens (the link page, with the token
 * after "#"). For an app using the parts without the handler, which does this itself. An undo link goes in the
 * "email-changed" message instead, which also names the new address.
 */
export function messageFor(link: Link, url: string): Message {
  if (link.kind === "undo") throw new Error('An undo link goes in an "email-changed" message, with the address the account moved to.');
  const to = { email: link.to };
  const { expires } = link;
  if (link.token === null) return { kind: link.refused, to };
  if (link.kind === "email") return { kind: "confirm-email", to, link: url, expires };
  if (!link.account) return { kind: "sign-up", to, link: url, expires };
  return { kind: link.kind === "password" ? "new-password" : "sign-in", to, link: url, expires };
}

/** The site, as its emails name it: its origin, and (optionally) its name, such as "Example Club". */
export type Site = { origin: string; name?: string };

/** The site's name for its emails, if it has one: one short, plain line (text.ts says why). */
function siteName(name: unknown): string | null {
  if (name === undefined) return null;
  if (!isPlainLine(name, 60)) {
    throw new Error('name must be the site\'s name for its emails, such as "Example Club": up to 60 characters, on one line, with nothing invisible.');
  }
  return name;
}

/**
 * modest-auth's own email for a message, in plain text: its subject names the site (`name`, or else its host),
 * and its text names it with its host ("Example Club (example.org)"), which a copycat can't borrow.
 */
export function emailFor(message: Message, site: Site): { subject: string; text: string } {
  const name = siteName(site.name);
  const { origin, host } = new URL(site.origin);
  const title = name ?? host;
  const where = name ? `${name} (${host})` : host;
  /** The link, and how long it lasts from now: in minutes up to two hours, then in days. */
  const open = (link: string, expires: number, how = "") => {
    const minutes = Math.max(1, Math.ceil((expires - Date.now()) / MINUTE));
    const left = minutes <= 120 ? `${minutes} minutes` : `${Math.ceil(minutes / (24 * 60))} days`;
    return `within ${left}${how}:\n\n${link}\n\n`;
  };
  const notYou = "If it wasn't you, you can ignore this email.\n";
  switch (message.kind) {
    case "sign-up":
      return {
        subject: `Finish signing up to ${title}`,
        text: `To finish signing up to ${where}, open this link ${open(message.link, message.expires)}If you didn't ask to sign up, you can ignore this email: no account is made without it.\n`,
      };
    case "sign-in":
      return {
        subject: `Sign in to ${title}`,
        text: `To sign in to ${where}, open this link ${open(message.link, message.expires)}If you didn't ask to sign in, you can ignore this email.\n`,
      };
    case "new-password":
      return {
        subject: `Choose a new password for ${title}`,
        text: `To choose a new password for your account on ${where}, open this link ${open(message.link, message.expires)}Choosing one signs you out everywhere else. If you didn't ask, you can ignore this email: nothing changes without it.\n`,
      };
    case "no-account":
      return {
        subject: `Sign in to ${title}`,
        text: `Someone asked to sign in to ${where} with this email address, but there's no account for it. To make one, sign up at ${origin}\n\n${notYou}`,
      };
    case "passkey-only":
      return {
        subject: `Sign in to ${title}`,
        text: `Someone asked for a link to sign in to ${where} with this email address. Your account signs in with a passkey only, so no link is sent: use your passkey at ${origin}. If you've lost every passkey, ask the site to help you back in.\n\n${notYou}`,
      };
    case "confirm-email":
      return {
        subject: `Confirm your new email address on ${title}`,
        text: `To use this email address for your account on ${where}, open this link ${open(message.link, message.expires, ", in a browser where you're signed in to that account")}Using it signs you out everywhere. If you didn't ask, you can ignore this email: nothing changes without it.\n`,
      };
    case "email-in-use":
      return {
        subject: `Your email address on ${title}`,
        text: `Someone asked to use this email address for an account on ${where}, but it has an account of its own already, so nothing has changed.\n\n${notYou}`,
      };
    case "password-changed":
      return {
        subject: `Your password was changed on ${title}`,
        text: `The password for your account on ${where} was just changed, and every other session ended.\n\nIf it wasn't you, choose a new one now at ${origin} ("forgotten your password"), which also signs out whoever changed it and removes any passkeys.\n`,
      };
    case "passkey-added":
      return {
        subject: `A passkey was added on ${title}`,
        text: `A passkey named "${message.name}" was just added to your account on ${where}, so it can sign in.\n\nIf it wasn't you, sign in at ${origin} and remove it, which signs everyone else out. If your account has a password, choosing a new one by "forgotten your password" removes every passkey too.\n`,
      };
    case "passkey-removed":
      return {
        subject: `A passkey was removed on ${title}`,
        text: `A passkey named "${message.name}" was just removed from your account on ${where}, so it can no longer sign in, and every other session ended.\n\nIf it wasn't you, sign in at ${origin} and check your account's passkeys and sessions.\n`,
      };
    case "account-deleted":
      return {
        subject: `Your account was deleted on ${title}`,
        text: `Your account on ${where} was just deleted, with everything kept about it, and every session ended.\n\nIf it wasn't you, someone could sign in to it: sign up again at ${origin}, and keep this address's inbox safe.\n`,
      };
    case "email-changed":
      return {
        subject: `Your email address was changed on ${title}`,
        text: `The email address for your account on ${where} was just changed from this one to ${message.email}, and every session ended.\n\nIf it wasn't you, undo it ${open(message.link, message.expires, " at this link, which moves the account back to this address, signs everyone out, and sends you a link to get back in")}`,
      };
  }
}
