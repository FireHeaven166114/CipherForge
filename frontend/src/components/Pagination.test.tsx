import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import Pagination from "./Pagination";

describe("Pagination", () => {
  it("shows the range and moves one page at a time", async () => {
    const onPageChange = vi.fn();
    const user = userEvent.setup();
    render(<Pagination page={2} pageSize={25} total={60} onPageChange={onPageChange} />);

    expect(screen.getByText("Showing 26–50 of 60")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(onPageChange).toHaveBeenNthCalledWith(1, 1);
    expect(onPageChange).toHaveBeenNthCalledWith(2, 3);
  });

  it("disables Previous on the first page and Next on the last, and ends the range at the total", () => {
    const { rerender } = render(
      <Pagination page={1} pageSize={25} total={60} onPageChange={vi.fn()} />,
    );
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();

    rerender(<Pagination page={3} pageSize={25} total={60} onPageChange={vi.fn()} />);
    expect(screen.getByText("Showing 51–60 of 60")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });

  it("explains the limit when the API will not serve further pages", () => {
    render(<Pagination page={2} pageSize={10} total={100} maxPage={2} onPageChange={vi.fn()} />);

    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(screen.getByText(/Only the first 20 results can be browsed/)).toBeInTheDocument();
  });

  it("does not mention a limit it has not reached", () => {
    render(<Pagination page={2} pageSize={10} total={15} maxPage={2} onPageChange={vi.fn()} />);

    expect(screen.queryByText(/can be browsed/)).not.toBeInTheDocument();
  });

  it("renders nothing when there are no results", () => {
    const { container } = render(
      <Pagination page={1} pageSize={25} total={0} onPageChange={vi.fn()} />,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
