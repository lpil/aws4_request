export function now() {
  const date = new Date();
  return [
    [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate()],
    [date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()],
  ];
}
