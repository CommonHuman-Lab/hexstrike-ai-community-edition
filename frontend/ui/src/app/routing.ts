export type Page =
  | 'dashboard'
  | 'settings'
  | 'help'
  | 'logs'
  | 'run'
  | 'tasks'
  | 'tools'
  | 'plugins'
  | 'reports'
  | 'sessions'
  | 'session-detail'
  | 'loot'
  | 'verify'
  | 'workbench'
  | 'payload-workbench';

const VALID_PAGES = new Set<Page>([
  'dashboard',
  'settings',
  'help',
  'logs',
  'run',
  'tasks',
  'tools',
  'plugins',
  'reports',
  'sessions',
  'session-detail',
  'loot',
  'verify',
  'workbench',
  'payload-workbench',
]);

export function buildWorkbenchHash(
  operationId: string | null,
  recipeJson: string | null,
  inputText?: string | null
): string {
  const path = operationId ? `/workbench/${encodeURIComponent(operationId)}` : '/workbench';
  const params = new URLSearchParams();
  if (recipeJson) params.set('recipe', recipeJson);
  if (inputText) params.set('input', inputText);
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function buildPayloadWorkbenchHash(operationId: string | null): string {
  return operationId ? `/payload-workbench/${encodeURIComponent(operationId)}` : '/payload-workbench';
}

export function routeFromHash(): {
  page: Page;
  sessionId: string | null;
  toolName: string | null;
  workbenchOperationId: string | null;
  workbenchRecipe: string | null;
  workbenchInput: string | null;
  payloadWorkbenchOperationId: string | null;
} {
  const hash = window.location.hash.replace(/^#\/?/, '');
  if (hash.startsWith('sessions/')) {
    const sessionId = hash.slice('sessions/'.length);
    return {
      page: 'session-detail',
      sessionId: sessionId || null,
      toolName: null,
      workbenchOperationId: null,
      workbenchRecipe: null,
      workbenchInput: null,
      payloadWorkbenchOperationId: null,
    };
  }
  if (hash.startsWith('run/')) {
    const toolName = decodeURIComponent(hash.slice('run/'.length));
    return {
      page: 'run',
      sessionId: null,
      toolName: toolName || null,
      workbenchOperationId: null,
      workbenchRecipe: null,
      workbenchInput: null,
      payloadWorkbenchOperationId: null,
    };
  }
  if (hash === 'workbench' || hash.startsWith('workbench/') || hash.startsWith('workbench?')) {
    const [pathPart, queryPart] = hash.slice('workbench'.length).split('?');
    const operationId = pathPart.startsWith('/') ? decodeURIComponent(pathPart.slice(1)) : '';
    const query = new URLSearchParams(queryPart ?? '');
    return {
      page: 'workbench',
      sessionId: null,
      toolName: null,
      workbenchOperationId: operationId || null,
      workbenchRecipe: query.get('recipe'),
      workbenchInput: query.get('input'),
      payloadWorkbenchOperationId: null,
    };
  }
  if (hash === 'payload-workbench' || hash.startsWith('payload-workbench/')) {
    const pathPart = hash.slice('payload-workbench'.length);
    const operationId = pathPart.startsWith('/') ? decodeURIComponent(pathPart.slice(1)) : '';
    return {
      page: 'payload-workbench',
      sessionId: null,
      toolName: null,
      workbenchOperationId: null,
      workbenchRecipe: null,
      workbenchInput: null,
      payloadWorkbenchOperationId: operationId || null,
    };
  }

  return {
    page: VALID_PAGES.has(hash as Page) ? (hash as Page) : 'dashboard',
    sessionId: null,
    toolName: null,
    workbenchOperationId: null,
    workbenchRecipe: null,
    workbenchInput: null,
    payloadWorkbenchOperationId: null,
  };
}
