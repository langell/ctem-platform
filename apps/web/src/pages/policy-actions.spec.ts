import { describe, expect, it } from 'vitest';
import { actionSelectValue, actionsFromSelect, editorActionsFromPolicy } from './policy-actions';

describe('editor notify vs ticket', () => {
  it('keeps notify and ticket from a stored policy and drops fail_build', () => {
    expect(editorActionsFromPolicy(['notify'])).toEqual(['notify']);
    expect(editorActionsFromPolicy(['ticket'])).toEqual(['ticket']);
    expect(editorActionsFromPolicy(['notify', 'ticket'])).toEqual(['notify', 'ticket']);
    expect(editorActionsFromPolicy(['ticket', 'fail_build'])).toEqual(['ticket']);
    expect(editorActionsFromPolicy(['fail_build', 'block_deploy'])).toEqual(['notify']);
  });

  it('maps the editor select to notify, ticket, or both — never fail_build', () => {
    expect(actionsFromSelect('notify')).toEqual(['notify']);
    expect(actionsFromSelect('ticket')).toEqual(['ticket']);
    expect(actionsFromSelect('notify,ticket')).toEqual(['notify', 'ticket']);
    expect(actionsFromSelect('fail_build')).toEqual(['notify']);
    expect(actionSelectValue(['notify'])).toBe('notify');
    expect(actionSelectValue(['ticket'])).toBe('ticket');
    expect(actionSelectValue(['notify', 'ticket'])).toBe('notify,ticket');
  });
});
