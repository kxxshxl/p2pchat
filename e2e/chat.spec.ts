/**
 * End-to-end: every test drives two (or more) independent browser profiles against a real
 * server, so keys, vaults, ratchets and WebRTC links are all exercised for real.
 */

import { DatabaseSync } from "node:sqlite";
import { generateIdentity, generateSignedPreKey, toBase64 } from "@parley/crypto";
import { expect, test, type Browser, type Page } from "@playwright/test";
import { E2E_DB } from "../playwright.config";

const PASSPHRASE = "correct horse battery staple";
let counter = 0;

/** Unique handles per test so tests don't depend on each other. */
function handle(name: string): string {
  return `${name.toLowerCase()}${Date.now().toString(36).slice(-4)}${counter++}`;
}

async function newUser(browser: Browser, name: string) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(err.message));
  const id = handle(name);
  await page.goto("/");
  await page.getByRole("tab", { name: "Create account" }).click();
  await page.getByPlaceholder("ada", { exact: true }).fill(id);
  await page.getByPlaceholder("Ada Lovelace").fill(name);
  await page.locator("input[type=password]").nth(0).fill(PASSPHRASE);
  await page.locator("input[type=password]").nth(1).fill(PASSPHRASE);
  await page.getByRole("button", { name: /Generate keys/ }).click();
  await expect(page.getByText("Connected")).toBeVisible({ timeout: 30_000 });
  return { page, context, handle: id, errors };
}

async function openChat(page: Page, peerHandle: string) {
  await page.getByLabel("Find people by handle").fill(peerHandle);
  await page.locator(".search-results button").first().click();
  await expect(page.locator(".conv-head")).toContainText(`@${peerHandle}`);
}

async function send(page: Page, text: string) {
  const box = page.locator(".composer textarea");
  await box.fill(text);
  await box.press("Enter");
}

const lastOut = (page: Page) => page.locator(".msg.out").last();

test("relay first, then a direct WebRTC link, receipts, typing and safety numbers", async ({ browser }) => {
  const alice = await newUser(browser, "Alice");
  const bob = await newUser(browser, "Bob");

  // Bob hasn't added Alice, so he refuses a direct link (it would expose his IP): relayed.
  await openChat(alice.page, bob.handle);
  await send(alice.page, "hello over the relay");
  await expect(lastOut(alice.page).getByLabel("relayed")).toBeVisible();

  await expect(bob.page.locator(".contact .badge")).toHaveText("1");
  await bob.page.locator(".contact").first().click();
  await expect(bob.page.locator(".msg.in .bubble").last()).toHaveText("hello over the relay");
  await expect(lastOut(alice.page).getByLabel("read")).toBeVisible();

  await send(bob.page, "hi alice");
  await expect(alice.page.locator(".msg.in .bubble").last()).toHaveText("hi alice");

  // Now both are contacts and online: the data channel opens and messages skip the server.
  await expect(alice.page.locator(".chip.p2p")).toBeVisible({ timeout: 20_000 });
  await expect(bob.page.locator(".chip.p2p")).toBeVisible({ timeout: 20_000 });
  await send(alice.page, "straight to you");
  await expect(lastOut(alice.page).getByLabel("sent directly")).toBeVisible();
  await expect(bob.page.locator(".msg.in").last().getByLabel("sent directly")).toBeVisible();

  await bob.page.locator(".composer textarea").pressSequentially("typing…", { delay: 30 });
  await expect(alice.page.locator(".typing")).toContainText("is typing");

  await alice.page.getByRole("button", { name: "Safety number" }).click();
  await bob.page.getByRole("button", { name: "Safety number" }).click();
  const a = await alice.page.locator(".safety-grid").innerText();
  const b = await bob.page.locator(".safety-grid").innerText();
  expect(a.replace(/\s/g, "")).toMatch(/^\d{60}$/);
  expect(a).toBe(b);

  expect([...alice.errors, ...bob.errors]).toEqual([]);
});

test("messages wait in the encrypted mailbox while the recipient is offline", async ({ browser }) => {
  const alice = await newUser(browser, "Alice");
  const bob = await newUser(browser, "Bob");
  await openChat(alice.page, bob.handle);
  await send(alice.page, "first");
  await expect(bob.page.locator(".contact")).toHaveCount(1);

  await bob.page.close();
  await send(alice.page, "while you were away");
  await expect(lastOut(alice.page).getByLabel("sent", { exact: true })).toBeVisible();

  const page = await bob.context.newPage();
  await page.goto("/");
  await page.getByLabel("Passphrase").fill("not the passphrase");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByRole("alert")).toContainText("Wrong passphrase");
  await page.getByLabel("Passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock" }).click();
  await page.locator(".contact").first().click();
  await expect(page.locator(".msg.in .bubble")).toHaveText(["first", "while you were away"]);
  await expect(lastOut(alice.page).getByLabel("read")).toBeVisible();
});

test("a key substituted by the server is detected and sending is blocked", async ({ browser }) => {
  const carol = await newUser(browser, "Carol");
  const dave = await newUser(browser, "Dave");
  await openChat(carol.page, dave.handle); // Dave's real keys are pinned now

  // Simulate a malicious directory: replace Dave's published identity and pre-keys.
  const db = new DatabaseSync(E2E_DB);
  const fake = generateIdentity();
  const spk = generateSignedPreKey(fake, 1);
  const { id } = db.prepare("SELECT id FROM users WHERE handle = ?").get(dave.handle) as { id: string };
  db.prepare("UPDATE users SET signing_key = ?, identity_key = ?, identity_key_sig = ? WHERE id = ?").run(
    toBase64(fake.signing.publicKey),
    toBase64(fake.dh.publicKey),
    toBase64(fake.dhSignature),
    id,
  );
  db.prepare("DELETE FROM one_time_prekeys WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM signed_prekeys WHERE user_id = ?").run(id);
  db.prepare("INSERT INTO signed_prekeys VALUES (?, ?, ?, ?, ?)").run(
    id,
    1,
    toBase64(spk.keyPair.publicKey),
    toBase64(spk.signature),
    Date.now(),
  );
  db.close();

  await send(carol.page, "the secret plan");
  await expect(carol.page.locator(".banner.danger")).toContainText("identity key changed");
  await expect(lastOut(carol.page).locator(".status-failed").first()).toBeVisible();
  await expect(carol.page.locator(".composer textarea")).toBeDisabled();
  await expect(dave.page.locator(".msg.in")).toHaveCount(0);
});

test("simultaneous session initiation converges", async ({ browser }) => {
  const erin = await newUser(browser, "Erin");
  const frank = await newUser(browser, "Frank");
  await openChat(erin.page, frank.handle);
  await openChat(frank.page, erin.handle);

  await erin.page.locator(".composer textarea").fill("from erin");
  await frank.page.locator(".composer textarea").fill("from frank");
  await Promise.all([
    erin.page.locator(".composer textarea").press("Enter"),
    frank.page.locator(".composer textarea").press("Enter"),
  ]);
  await expect(erin.page.locator(".msg.in .bubble")).toHaveText(["from frank"]);
  await expect(frank.page.locator(".msg.in .bubble")).toHaveText(["from erin"]);

  for (let i = 0; i < 3; i++) {
    await send(erin.page, `e${i}`);
    await send(frank.page, `f${i}`);
  }
  await expect(frank.page.locator(".msg.in .bubble").last()).toHaveText("e2");
  await expect(erin.page.locator(".msg.in .bubble").last()).toHaveText("f2");
  await expect(erin.page.locator(".system-msg")).toHaveCount(0);
  await expect(frank.page.locator(".system-msg")).toHaveCount(0);
});
