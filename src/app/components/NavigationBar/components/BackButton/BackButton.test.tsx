import { createMemoryHistory } from "history";
import React from "react";
import { fireEvent, render } from "utils/testing-library";

import { BackButton } from "./BackButton";
const history = createMemoryHistory();

describe("BackButton", () => {
	it("should render", () => {
		const { container } = render(<BackButton />, { history });

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();
	});

	it("should render when disabled", () => {
		const { container } = render(<BackButton disabled />, { history });

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();
	});

	it("should redirect to previous page", () => {
		const historySpy = jest.spyOn(history, "go").mockImplementation();

		const { container, getByRole } = render(<BackButton />, { history });

		fireEvent.click(getByRole("button"));

		expect(historySpy).toHaveBeenCalledWith(-1);

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();

		historySpy.mockRestore();
	});

	it("should redirect to given url", () => {
		const historySpy = jest.spyOn(history, "push").mockImplementation();

		const { container, getByRole } = render(<BackButton backToUrl="new-url" />, { history });

		fireEvent.click(getByRole("button"));

		expect(historySpy).toHaveBeenCalledWith("new-url");

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();

		historySpy.mockRestore();
	});

	it("should not redirect to previous page when disabled", () => {
		const historySpy = jest.spyOn(history, "go").mockImplementation();

		const { container, getByRole } = render(<BackButton disabled />, { history });

		fireEvent.click(getByRole("button"));

		expect(historySpy).not.toHaveBeenCalled();

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();

		historySpy.mockRestore();
	});

	it("should not redirect to given url when disabled", () => {
		const historySpy = jest.spyOn(history, "push").mockImplementation();

		const { container, getByRole } = render(<BackButton backToUrl="new-url" disabled />, { history });

		fireEvent.click(getByRole("button"));

		expect(historySpy).not.toHaveBeenCalled();

		expect(container).toHaveTextContent("chevron-left-small.svg");
		expect(container).toMatchSnapshot();

		historySpy.mockRestore();
	});
});
