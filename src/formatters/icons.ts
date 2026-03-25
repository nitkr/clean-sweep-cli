export const icons = {
  scanning: '🔍',
  error: '❌',
  safe: '✅',
  warning: '⚠️',
  info: '🛡️',
};

export function getIcon(status: string): string {
  switch (status.toLowerCase()) {
    case 'scanning':
    case 'in-progress':
    case 'running':
      return icons.scanning;
    case 'error':
    case 'threat':
    case 'danger':
    case 'critical':
    case 'unsafe':
      return icons.error;
    case 'safe':
    case 'healthy':
    case 'success':
    case 'ok':
      return icons.safe;
    case 'warning':
    case 'medium':
    case 'high':
      return icons.warning;
    case 'info':
    case 'low':
    case 'protected':
      return icons.info;
    default:
      return '';
  }
}

export function severityIcon(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return icons.error;
    case 'high':
      return icons.warning;
    case 'medium':
      return icons.warning;
    case 'low':
      return icons.info;
    case 'info':
      return icons.info;
    default:
      return '';
  }
}
