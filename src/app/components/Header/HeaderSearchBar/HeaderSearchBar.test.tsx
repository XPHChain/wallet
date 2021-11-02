/* eslint-disable @typescript-eslint/require-await */
import React from "react";
import { act, fireEvent, render, screen, waitFor } from "utils/testing-library";

import { HeaderSearchBar } from "./HeaderSearchBar";

describe("HeaderSearchBar", () => {
	it("should render", () => {
		const { asFragment } = render(<HeaderSearchBar />);

		expect(screen.getByRole("button")).toHaveTextContent("Search");
		expect(asFragment()).toMatchSnapshot();
	});

	it("should show the searchbar", () => {
		render(<HeaderSearchBar />);

		fireEvent.click(screen.getByRole("button"));

		expect(screen.getByTestId("HeaderSearchBar__input")).toBeInTheDocument();
	});

	it("should limit search letters", async () => {
		render(<HeaderSearchBar maxLength={32} />);

		fireEvent.click(screen.getByRole("button"));

		const input = screen.getByTestId("Input") as HTMLInputElement;

		expect(input.maxLength).toBe(32);

		const text = "loong text";
		const longText = text.repeat(100);

		act(() => {
			fireEvent.input(input, { target: { value: longText } });
		});

		await waitFor(() => expect(input.value).toBe(text.repeat(100)));
		expect(input.value.length).toBe(1000);
	});

	it("should reset fields by prop", async () => {
		const onReset = jest.fn();
		const { rerender } = render(<HeaderSearchBar onReset={onReset} />);

		fireEvent.click(screen.getByRole("button"));

		const input = screen.getByTestId("Input") as HTMLInputElement;

		act(() => {
			fireEvent.change(input, {
				target: {
					value: "test",
				},
			});
		});

		expect(input.value).toBe("test");

		rerender(<HeaderSearchBar onReset={onReset} resetFields={true} />);

		await waitFor(() => expect(input.value).not.toBe("test"));

		expect(onReset).toHaveBeenCalled();
	});

	it("should show extra slot", () => {
		render(<HeaderSearchBar extra={<div data-testid="extra-slot" />} />);

		fireEvent.click(screen.getByRole("button"));

		expect(screen.getByTestId("extra-slot")).toBeInTheDocument();
	});

	it("should hide the searchbar when clicked outside", () => {
		const onSearch = jest.fn();

		render(
			<div>
				<div data-testid="header-search-bar__outside" className="mt-16">
					outside elememt to be clicked
				</div>

				<HeaderSearchBar onSearch={onSearch} />
			</div>,
		);

		fireEvent.click(screen.getByRole("button"));

		const outsideElement = screen.getByTestId("header-search-bar__outside");

		expect(outsideElement).toBeInTheDocument();

		expect(screen.getByTestId("Input")).toBeInTheDocument();

		act(() => {
			fireEvent.mouseDown(outsideElement);
		});

		expect(() => screen.getByTestId("Input")).toThrow(/Unable to find an element by/);
	});

	it("should reset the query", () => {
		const onReset = jest.fn();
		render(<HeaderSearchBar onReset={onReset} />);

		fireEvent.click(screen.getByRole("button"));

		const input = screen.getByTestId("Input") as HTMLInputElement;

		act(() => {
			fireEvent.change(input, {
				target: {
					value: "test",
				},
			});
		});

		expect(input.value).toBe("test");

		act(() => {
			fireEvent.click(screen.getByTestId("header-search-bar__reset"));
		});

		expect(input.value).not.toBe("test");
		expect(onReset).toHaveBeenCalled();
	});

	it("should call onSearch", async () => {
		jest.useFakeTimers();

		const onSearch = jest.fn();

		render(<HeaderSearchBar onSearch={onSearch} />);

		fireEvent.click(screen.getByRole("button"));

		act(() => {
			fireEvent.change(screen.getByTestId("Input"), {
				target: {
					value: "test",
				},
			});
		});

		await act(async () => {
			jest.runAllTimers();
		});

		expect(onSearch).toHaveBeenCalled();
	});

	it("should set custom debounce timeout form props", async () => {
		jest.useFakeTimers();

		const onSearch = jest.fn();

		render(<HeaderSearchBar onSearch={onSearch} debounceTimeout={100} />);

		fireEvent.click(screen.getByRole("button"));

		act(() => {
			fireEvent.change(screen.getByTestId("Input"), {
				target: {
					value: "test",
				},
			});
		});

		await act(async () => {
			jest.runAllTimers();
		});

		expect(onSearch).toHaveBeenCalled();
	});
});
