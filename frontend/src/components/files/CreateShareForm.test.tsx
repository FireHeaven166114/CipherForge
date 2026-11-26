import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  FILE_ID,
  SHARE_TOKEN,
  failure,
  makeFileStatus,
  makeGate,
  only,
  serveVault,
  takeStrayRequests,
} from "../../test/filesFixtures";
import type { ShareCreated } from "../../types/files";
import CreateShareForm from "./CreateShareForm";

const HOURS = "Expires after (hours)";
const DOWNLOADS = "Maximum downloads";
const PASSWORD = "Password (optional)";
const SHARES_PATH = `/api/v1/files/${FILE_ID}/shares`;

afterEach(() => {
  expect(takeStrayRequests()).toEqual([]);
});

function renderForm(props: Partial<ComponentProps<typeof CreateShareForm>> = {}) {
  const onCreated = vi.fn<(created: ShareCreated) => void>();
  render(
    <CreateShareForm
      fileId={FILE_ID}
      status={makeFileStatus()}
      blockedReason={null}
      onCreated={onCreated}
      {...props}
    />,
  );
  return { onCreated };
}

const isCreate = (method: string, path: string) => method === "POST" && path === SHARES_PATH;

function createButton() {
  return screen.getByRole("button", { name: "Create link" });
}

describe("CreateShareForm", () => {
  it.each([
    { defaultHours: 24, maxHours: 720, shown: 24 },
    { defaultHours: 48, maxHours: 720, shown: 48 },
    { defaultHours: 24, maxHours: 12, shown: 12 },
  ])(
    "starts at $shown hours when the server defaults to $defaultHours and allows $maxHours",
    ({ defaultHours, maxHours, shown }) => {
      renderForm({
        status: makeFileStatus({ default_share_expiry_hours: defaultHours, max_share_expiry_hours: maxHours }),
      });

      expect(screen.getByLabelText(HOURS)).toHaveValue(shown);
      expect(screen.getByLabelText(DOWNLOADS)).toHaveValue(1);
    },
  );

  it("takes its limits from the server and keeps browsers from filling in the password", () => {
    renderForm({ status: makeFileStatus({ min_password_length: 12, max_password_length: 64 }) });

    const password = screen.getByLabelText(PASSWORD);
    expect(password).toHaveValue("");
    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveAttribute("autocomplete", "new-password");
    expect(password).toHaveAccessibleDescription(expect.stringContaining("12 to 64 characters"));
    expect(screen.getByLabelText(HOURS)).toHaveAccessibleDescription(
      "1 to 720 hours. The link stops working after that.",
    );
    expect(screen.getByLabelText(DOWNLOADS)).toHaveAccessibleDescription(
      "1 to 100. The link stops working after this many downloads.",
    );
  });

  it("shows the password only while asked to, and counts what was typed", async () => {
    const user = userEvent.setup();
    renderForm();
    const password = screen.getByLabelText(PASSWORD);

    await user.type(password, "hunter22!");

    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveAccessibleDescription(expect.stringContaining("Typed so far: 9."));

    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(password).toHaveAttribute("type", "text");

    await user.click(screen.getByRole("button", { name: "Hide password" }));
    expect(password).toHaveAttribute("type", "password");
  });

  const INVALID = [
    { name: "no hours", label: HOURS, value: "", message: "Enter a whole number of hours from 1 to 720." },
    { name: "0 hours", label: HOURS, value: "0", message: "Enter a whole number of hours from 1 to 720." },
    { name: "721 hours", label: HOURS, value: "721", message: "Enter a whole number of hours from 1 to 720." },
    {
      name: "0 downloads",
      label: DOWNLOADS,
      value: "0",
      message: "Enter a whole number of downloads from 1 to 100.",
    },
    {
      name: "101 downloads",
      label: DOWNLOADS,
      value: "101",
      message: "Enter a whole number of downloads from 1 to 100.",
    },
    {
      name: "a password of 5 characters",
      label: PASSWORD,
      value: "short",
      message: "Use at least 8 characters, or leave the password empty for no password.",
    },
    {
      name: "a password of 129 characters",
      label: PASSWORD,
      value: "x".repeat(129),
      message: "Use at most 128 characters.",
    },
  ];

  it.each(INVALID)("rejects $name as it is typed, and sends nothing", async ({ label, value, message }) => {
    const vault = serveVault();
    const user = userEvent.setup();
    renderForm();
    const field = screen.getByLabelText(label);
    expect(field).toBeValid();

    fireEvent.change(field, { target: { value } });

    expect(field).toBeInvalid();
    expect(screen.getByText(message)).toBeInTheDocument();
    expect(field).toHaveAccessibleDescription(expect.stringContaining(message));

    await user.click(createButton());

    expect(vault.changes()).toEqual([]);
    expect(field).toHaveFocus();
  });

  it("sends focus to the first of several wrong fields", async () => {
    const vault = serveVault();
    const user = userEvent.setup();
    renderForm();
    fireEvent.change(screen.getByLabelText(DOWNLOADS), { target: { value: "500" } });
    fireEvent.change(screen.getByLabelText(PASSWORD), { target: { value: "short" } });

    await user.click(createButton());

    expect(screen.getByLabelText(DOWNLOADS)).toHaveFocus();
    expect(screen.getByLabelText(PASSWORD)).toBeInvalid();
    expect(vault.changes()).toEqual([]);
  });

  it("asks for numbers, and for a password only when one was typed", async () => {
    const vault = serveVault();
    const user = userEvent.setup();
    const { onCreated } = renderForm();

    await user.click(createButton());

    await waitFor(() => expect(onCreated).toHaveBeenCalledOnce());
    const withoutPassword = only(vault.changes());
    expect(withoutPassword.method).toBe("POST");
    expect(withoutPassword.path).toBe(SHARES_PATH);
    expect(withoutPassword.body).toStrictEqual({ expires_in_hours: 24, max_downloads: 1 });

    const hours = screen.getByLabelText(HOURS);
    const downloads = screen.getByLabelText(DOWNLOADS);
    await user.clear(hours);
    await user.type(hours, "72");
    await user.clear(downloads);
    await user.type(downloads, "5");
    await user.type(screen.getByLabelText(PASSWORD), "correct horse");
    await user.click(createButton());

    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(2));
    expect(vault.changes()[1]?.body).toStrictEqual({
      expires_in_hours: 72,
      max_downloads: 5,
      password: "correct horse",
    });
  });

  it("hands over the answer, with the link's token, and goes back to its defaults", async () => {
    serveVault();
    const user = userEvent.setup();
    const { onCreated } = renderForm();
    const hours = screen.getByLabelText(HOURS);
    await user.clear(hours);
    await user.type(hours, "72");
    await user.type(screen.getByLabelText(PASSWORD), "correct horse");
    await user.click(screen.getByRole("button", { name: "Show password" }));

    await user.click(createButton());

    await waitFor(() => expect(onCreated).toHaveBeenCalledOnce());
    const created = onCreated.mock.calls[0]?.[0];
    expect(created?.token).toBe(SHARE_TOKEN);
    expect(created?.path).toBe(`/share/${SHARE_TOKEN}`);
    expect(created?.share.password_protected).toBe(true);

    // Nothing typed is kept once the link exists: the password least of all.
    expect(screen.getByLabelText(HOURS)).toHaveValue(24);
    const password = screen.getByLabelText(PASSWORD);
    expect(password).toHaveValue("");
    expect(password).toHaveAttribute("type", "password");
    expect(screen.queryByText(/Typed so far/)).not.toBeInTheDocument();
  });

  it("says why a link was refused, keeps what was typed, and tries again on the same button", async () => {
    let attempts = 0;
    const vault = serveVault({
      override: ({ method, path }) =>
        isCreate(method, path) && ++attempts === 1
          ? failure(429, "rate_limited", { "Retry-After": "5" })
          : undefined,
    });
    const user = userEvent.setup();
    const { onCreated } = renderForm();
    await user.type(screen.getByLabelText(PASSWORD), "correct horse");

    await user.click(createButton());

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The link could not be created");
    expect(alert).toHaveTextContent("Too many requests. Try again in 5 seconds.");
    expect(alert).toHaveTextContent("Reference: req-test");
    expect(onCreated).not.toHaveBeenCalled();
    expect(screen.getByLabelText(PASSWORD)).toHaveValue("correct horse");
    expect(createButton()).not.toHaveAttribute("aria-disabled");

    await user.click(createButton());

    await waitFor(() => expect(onCreated).toHaveBeenCalledOnce());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(2);
  });

  it("makes one link however often the button is pressed, and says it is working", async () => {
    const gate = makeGate();
    const vault = serveVault({
      override: async ({ method, path }) => {
        if (isCreate(method, path)) await gate.passed;
        return undefined;
      },
    });
    const user = userEvent.setup();
    const { onCreated } = renderForm();

    await user.dblClick(createButton());

    const busy = await screen.findByRole("button", { name: "Creating link…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.click(busy);
    expect(vault.changes()).toHaveLength(1);
    expect(onCreated).not.toHaveBeenCalled();

    gate.open();

    await waitFor(() => expect(onCreated).toHaveBeenCalledOnce());
    expect(vault.changes()).toHaveLength(1);
    expect(createButton()).not.toHaveAttribute("aria-disabled");
  });

  it("explains why it is switched off, and cannot be used", async () => {
    const vault = serveVault();
    const user = userEvent.setup();
    const { onCreated } = renderForm({
      blockedReason: "This file failed its integrity check, so it cannot be shared.",
    });
    const form = screen.getByRole("form", { name: "Create a share link" });

    expect(within(form).getByText("This file failed its integrity check, so it cannot be shared.")).toBeInTheDocument();
    expect(screen.getByLabelText(HOURS)).toBeDisabled();
    expect(screen.getByLabelText(DOWNLOADS)).toBeDisabled();
    expect(screen.getByLabelText(PASSWORD)).toBeDisabled();
    expect(createButton()).toBeDisabled();

    await user.click(createButton());
    fireEvent.submit(form);

    expect(vault.changes()).toEqual([]);
    expect(onCreated).not.toHaveBeenCalled();
  });
});
