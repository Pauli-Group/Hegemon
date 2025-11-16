const DEFAULT_SERVICE_URL = 'http://localhost:8001';

export function sanitizeBaseUrl(url: string) {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

export const defaultDashboardServiceUrl = sanitizeBaseUrl(
  import.meta.env.VITE_DASHBOARD_SERVICE_URL || DEFAULT_SERVICE_URL
);
