import { describe, expect, it } from 'vitest';
import { actionSelectValue, actionsFromSelect, editorActionsFromPolicy } from './policy-actions';

describe('editor notify, ticket, or fail-build', () => {
  it('keeps notify, ticket, and fail_build from a stored policy and drops block_deploy', () => {
    expect(editorActionsFromPolicy(['notify'])).toEqual(['notify']);
    expect(editorActionsFromPolicy(['ticket'])).toEqual(['ticket']);
    expect(editorActionsFromPolicy(['fail_build'])).toEqual(['fail_build']);
    expect(editorActionsFromPolicy(['notify', 'ticket'])).toEqual(['notify', 'ticket']);
    expect(editorActionsFromPolicy(['ticket', 'fail_build'])).toEqual(['ticket', 'fail_build']);
    expect(editorActionsFromPolicy(['fail_build', 'block_deploy'])).toEqual(['fail_build']);
    expect(editorActionsFromPolicy(['block_deploy'])).toEqual(['notify']);
  });

  it('maps the editor select to notify, ticket, fail_build, or combinations', () => {
    expect(actionsFromSelect('notify')).toEqual(['notify']);
    expect(actionsFromSelect('ticket')).toEqual(['ticket']);
    expect(actionsFromSelect('fail_build')).toEqual(['fail_build']);
    expect(actionsFromSelect('notify,ticket')).toEqual(['notify', 'ticket']);
    expect(actionsFromSelect('notify,fail_build')).toEqual(['notify', 'fail_build']);
    expect(actionsFromSelect('block_deploy')).toEqual(['notify']);
    expect(actionSelectValue(['notify'])).toBe('notify');
    expect(actionSelectValue(['ticket'])).toBe('ticket');
    expect(actionSelectValue(['fail_build'])).toBe('fail_build');
    expect(actionSelectValue(['notify', 'ticket'])).toBe('notify,ticket');
    expect(actionSelectValue(['notify', 'fail_build'])).toBe('notify,fail_build');
  });
});
