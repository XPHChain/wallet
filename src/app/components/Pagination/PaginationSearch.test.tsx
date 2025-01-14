import React from "react";
import { fireEvent, render, waitFor } from "utils/testing-library";

import { PaginationSearch } from "./PaginationSearch";

describe("PaginationSearch", () => {
	it("should render", async () => {
		const { asFragment, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={jest.fn()} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();
	});

	it("should show pagination search input", async () => {
		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={jest.fn()} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");
	});

	it("should show search input and close", async () => {
		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={jest.fn()} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.click(getByTestId("PaginationSearch__cancel"));

		await waitFor(() => expect(() => getByTestId("PaginationSearchForm")).toThrow(/Unable to find an element by/));
	});

	it("should type page and emit onSelectPage event", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.input(getByTestId("PaginationSearch__input"), {
			target: {
				value: "1",
			},
		});

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(getByTestId("PaginationSearch__input")).toHaveValue(1));

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(onSelect).toHaveBeenCalledWith(1));
	});

	it("should not allow typing number greater than total pages", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.input(getByTestId("PaginationSearch__input"), {
			target: {
				value: "6",
			},
		});

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(getByTestId("PaginationSearch__input")).toHaveValue(5));

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(onSelect).toHaveBeenCalledWith(5));
	});

	it("should not emit onSelect if nothing is typed", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(onSelect).not.toHaveBeenCalled());
	});

	it("should not emit onSelect if zero is typed", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect} totalPages={5}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.input(getByTestId("PaginationSearch__input"), {
			target: {
				value: "0",
			},
		});

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(getByTestId("PaginationSearch__input")).toHaveValue(0));

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(onSelect).not.toHaveBeenCalled());
	});

	it("should not limit total page if not provided", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect}>
				<span data-testid="PaginationSearchToggle">...</span>
			</PaginationSearch>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.input(getByTestId("PaginationSearch__input"), {
			target: {
				value: "100000000",
			},
		});

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(getByTestId("PaginationSearch__input")).toHaveValue(100_000_000));

		fireEvent.click(getByTestId("PaginationSearch__submit"));

		await waitFor(() => expect(onSelect).toHaveBeenCalledWith(100_000_000));
	});

	it("should close search input if clicked outside", async () => {
		const onSelect = jest.fn();

		const { asFragment, getByTestId, findByTestId } = render(
			<div>
				<div data-testid="somewhere-outside" className="p-4">
					sample text
				</div>
				<PaginationSearch onClick={jest.fn()} onSelectPage={onSelect}>
					<span data-testid="PaginationSearchToggle">...</span>
				</PaginationSearch>
				,
			</div>,
		);

		await findByTestId("PaginationSearchToggle");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.click(getByTestId("PaginationSearchToggle"));

		await findByTestId("PaginationSearchForm");

		fireEvent.mouseDown(getByTestId("somewhere-outside"));

		await waitFor(() => expect(() => getByTestId("PaginationSearchForm")).toThrow(/Unable to find an element by/));
	});
});
