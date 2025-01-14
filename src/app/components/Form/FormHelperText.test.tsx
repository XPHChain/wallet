import React from "react";
import { render } from "utils/testing-library";

import { FormHelperText } from "./FormHelperText";
import { FormFieldProvider } from "./useFormField";

describe("FormHelperText", () => {
	it("should render hint text", () => {
		const hintMessage = "Test Message";
		const errorMessage = "Error Message";
		const { queryByText, asFragment } = render(
			<FormHelperText errorMessage={errorMessage}>{hintMessage}</FormHelperText>,
		);

		expect(queryByText(hintMessage)).toBeInTheDocument();
		expect(asFragment()).toMatchSnapshot();
	});

	it("should not show hint if is invalid", () => {
		const hintMessage = "Test Message";
		const { queryByText } = render(<FormHelperText isInvalid>{hintMessage}</FormHelperText>);

		expect(queryByText(hintMessage)).toBeNull();
	});

	it("should render error message", () => {
		const hintMessage = "Test Message";
		const errorMessage = "Error Message";
		const { queryByText, asFragment } = render(
			<FormHelperText errorMessage={errorMessage} isInvalid>
				{hintMessage}
			</FormHelperText>,
		);

		expect(queryByText(errorMessage)).toBeInTheDocument();
		expect(asFragment()).toMatchSnapshot();
	});

	it("should not render if nothing is provided", () => {
		const { container } = render(<FormHelperText />);

		expect(container).toMatchInlineSnapshot(`<div />`);
	});

	it("should read data from context", () => {
		const context = {
			errorMessage: "Error message from context",
			isInvalid: true,
			name: "test",
		};
		const tree = (
			<FormFieldProvider value={context}>
				<FormHelperText />
			</FormFieldProvider>
		);
		const { queryByText } = render(tree);

		expect(queryByText(context.errorMessage)).toBeInTheDocument();
	});
});
