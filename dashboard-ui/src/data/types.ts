export interface CommandSpec {
  argv: string[];
  cwd?: string;
  env?: Record<string, string>;
}

export interface DashboardAction {
  slug: string;
  title: string;
  description: string;
  category: string;
  notes?: string;
  commands: CommandSpec[];
}

export interface ActionExportPayload {
  generated_at: string;
  action_count: number;
  actions: DashboardAction[];
}
