import { EDITOR_ACTIONS, type EditorAction } from '../api/types';

/** Tenant editor may write notify and/or ticket. fail-build is not an option. */
export function editorActionsFromPolicy(actions: string[]): EditorAction[] {
  const picked = EDITOR_ACTIONS.filter((action) => actions.includes(action));
  return picked.length ? [...picked] : ['notify'];
}

export function actionSelectValue(actions: EditorAction[]): string {
  const notify = actions.includes('notify');
  const ticket = actions.includes('ticket');
  if (notify && ticket) return 'notify,ticket';
  if (ticket) return 'ticket';
  return 'notify';
}

export function actionsFromSelect(value: string): EditorAction[] {
  if (value === 'ticket') return ['ticket'];
  if (value === 'notify,ticket') return ['notify', 'ticket'];
  return ['notify'];
}
