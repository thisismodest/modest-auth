// Short names people or apps give (a site's name for its emails, a passkey's name): one plain line. A line break
// could add a line of its own to an email (a header, in a mail program that writes them), and an invisible
// character (one that reverses text, say) could disguise what's shown.

/** Whether `text` is one plain line of 1 to `most` characters, with no control, invisible, or line-separating characters, nor space at either end. */
export const isPlainLine = (text: unknown, most: number): text is string =>
  typeof text === "string" && text.length > 0 && text.length <= most && text.trim() === text && !/[\p{C}\p{Zl}\p{Zp}]/u.test(text);
