import { EDITOR_ACTIONS, type EditorAction } from '../api/types';

/** Tenant editor may write notify, ticket, and/or fail-build. block-deploy is not an option. */
export function editorActionsFromPolicy(actions: string[]): EditorAction[] {
  const picked = EDITOR_ACTIONS.filter((action) => actions.includes(action));
  return picked.length ? [...picked] : ['notify'];
}

export function actionSelectValue(actions: EditorAction[]): string {
  const picked = EDITOR_ACTIONS.filter((action) => actions.includes(action));
  return picked.length ? picked.join(',') : 'notify';
}

export function actionsFromSelect(value: string): EditorAction[] {
  const picked = value
    .split(',')
    .filter((action): action is EditorAction => (EDITOR_ACTIONS as readonly string[]).includes(action));
  return picked.length ? picked : ['notify'];
}
