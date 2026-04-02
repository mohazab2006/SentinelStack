/**
 * Stable across server (Node) and browser: same locale, options, and timezone.
 * Without a fixed timeZone, Docker/Node often uses UTC while the browser uses local time → hydration errors.
 */
const dateTimeFormatter = new Intl.DateTimeFormat("en-US", {
  dateStyle: "short",
  timeStyle: "medium",
  timeZone: "UTC"
});

export function formatDateTime(value: string): string {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return value;
  }
  return `${dateTimeFormatter.format(d)} UTC`;
}
