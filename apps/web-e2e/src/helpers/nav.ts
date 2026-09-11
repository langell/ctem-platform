import { expect, type Locator, type Page } from '@playwright/test';

/** Authenticated Owner Dock — primary nav lives here, not in a top bar. */
export function ownerDock(page: Page): Locator {
  return page.locator('aside.dock');
}

export async function clickOwnerDockLink(page: Page, name: string): Promise<void> {
  await ownerDock(page).getByRole('link', { name, exact: true }).click();
}

export async function expectOwnerDockActive(page: Page, name: string): Promise<void> {
  const link = ownerDock(page).getByRole('link', { name, exact: true });
  await expect(link).toHaveClass(/active/);
  await expect(link).toHaveAttribute('aria-current', 'page');
}
