export function expressToOpenAPI(path: string): string {
  return path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}
