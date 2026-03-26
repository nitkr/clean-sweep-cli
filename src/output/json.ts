export function outputJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function outputErrorJson(error: string | Error): void {
  console.log(JSON.stringify({ error: String(error) }, null, 2));
}
