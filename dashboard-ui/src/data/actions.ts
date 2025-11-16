import raw from './actions.json';
import type { ActionExportPayload, DashboardAction } from './types';

const exportPayload = raw as ActionExportPayload;

const normalizedActions: DashboardAction[] = exportPayload.actions.map((action) => ({
  ...action,
  notes: action.notes ?? undefined,
  commands: action.commands.map((command) => ({
    ...command,
    env: command.env ? { ...command.env } : undefined,
  })),
}));

export const actionMetadata = {
  generatedAt: exportPayload.generated_at,
  total: exportPayload.action_count,
};

export function listActions(): DashboardAction[] {
  return [...normalizedActions];
}

export function getActionBySlug(slug: string): DashboardAction | undefined {
  return normalizedActions.find((action) => action.slug === slug);
}

export function groupActionsByCategory(actionList: DashboardAction[] = normalizedActions) {
  const grouped = new Map<string, DashboardAction[]>();
  for (const action of actionList) {
    if (!grouped.has(action.category)) {
      grouped.set(action.category, []);
    }
    grouped.get(action.category)!.push(action);
  }
  return Array.from(grouped.entries())
    .map(([category, actions]) => ({
      category,
      actions: actions.sort((a, b) => a.slug.localeCompare(b.slug)),
    }))
    .sort((a, b) => a.category.localeCompare(b.category));
}

export function formatCommandLine(argv: string[]): string {
  return argv.join(' ');
}

export const quickstartAction = getActionBySlug('quickstart');
