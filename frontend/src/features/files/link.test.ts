import { afterEach, describe, expect, it, vi } from "vitest";

import { removeClipboardStubs, stubClipboard, stubExecCommand } from "../../test/filesFixtures";
import { buildShareLink, copyText } from "./link";

describe("buildShareLink", () => {
  it("puts the page's own origin in front of the path the API returned", () => {
    expect(buildShareLink("/share/abc", "https://cipherforge.example")).toBe("https://cipherforge.example/share/abc");
    expect(buildShareLink("/share/abc")).toBe(`${window.location.origin}/share/abc`);
  });

  it("adds the slash a path is missing", () => {
    expect(buildShareLink("share/abc", "https://cipherforge.example")).toBe("https://cipherforge.example/share/abc");
  });

  it("cannot be pointed at another site, however odd the path", () => {
    expect(buildShareLink("//evil.example/x", "https://cipherforge.example").startsWith("https://cipherforge.example/")).toBe(
      true,
    );
    expect(buildShareLink("https://evil.example/x", "https://cipherforge.example")).toBe(
      "https://cipherforge.example/https://evil.example/x",
    );
  });
});

describe("copyText", () => {
  afterEach(() => {
    removeClipboardStubs();
  });

  function input(value = "link") {
    const element = document.createElement("input");
    element.value = value;
    document.body.append(element);
    return element;
  }

  it("uses the clipboard API when the page has it", async () => {
    const writeText = stubClipboard();
    const execCommand = stubExecCommand();

    await expect(copyText("https://x.example/share/t", input())).resolves.toBe(true);

    expect(writeText).toHaveBeenCalledWith("https://x.example/share/t");
    expect(execCommand).not.toHaveBeenCalled();
  });

  it("selects the text and copies it the old way when the clipboard API refuses", async () => {
    stubClipboard(() => Promise.reject(new Error("denied")));
    const execCommand = stubExecCommand(true);
    const source = input("secret-link");
    const select = vi.spyOn(source, "select");

    await expect(copyText("secret-link", source)).resolves.toBe(true);

    expect(select).toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(source).toHaveFocus();
  });

  it("uses the old way when there is no clipboard API", async () => {
    const execCommand = stubExecCommand(true);
    await expect(copyText("text", input())).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("reports failure, leaving the text selected, when nothing could copy it", async () => {
    const source = input("secret-link");
    const select = vi.spyOn(source, "select");

    await expect(copyText("secret-link", source)).resolves.toBe(false);
    expect(select).toHaveBeenCalled();

    stubExecCommand(false);
    await expect(copyText("secret-link", source)).resolves.toBe(false);
  });

  it("reports failure when the old way throws or there is no input to select", async () => {
    const execCommand = stubExecCommand();
    execCommand.mockImplementation(() => {
      throw new Error("not allowed");
    });

    await expect(copyText("text", input())).resolves.toBe(false);
    await expect(copyText("text", null)).resolves.toBe(false);
  });
});
