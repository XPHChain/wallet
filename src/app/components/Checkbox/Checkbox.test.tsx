import React from "react";
import { Color } from "types";
import { render } from "utils/testing-library";

import { Checkbox } from "./Checkbox";

describe("Checkbox", () => {
	beforeAll(() => {
		jest.spyOn(console, "error").mockImplementation(() => null);
	});

	afterAll(() => {
		console.error.mockRestore();
	});

	it("should render", () => {
		const { container } = render(<Checkbox />);

		expect(container).toMatchSnapshot();
	});

	it.each(["info", "success", "warning", "danger", "hint"])("should render a %s color", (color) => {
		const { container } = render(<Checkbox color={color as Color} />);

		expect(container).toMatchSnapshot();
	});
});
