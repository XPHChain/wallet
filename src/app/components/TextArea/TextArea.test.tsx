import React from "react";
import { render } from "utils/testing-library";

import { TextArea } from "./TextArea";

describe("TextArea", () => {
	it("should render", () => {
		const { getByTestId, asFragment } = render(<TextArea ref={React.createRef()} />);
		const textarea = getByTestId("TextArea");

		expect(textarea.tagName).toBe("TEXTAREA");
		expect(asFragment()).toMatchSnapshot();
	});

	it("should render as invalid", () => {
		const { asFragment } = render(<TextArea isInvalid />);

		expect(asFragment()).toMatchSnapshot();
	});

	it("should render as disabled", () => {
		const { getByTestId, asFragment } = render(<TextArea disabled />);
		const textarea = getByTestId("TextArea");

		expect(textarea).toBeDisabled();
		expect(asFragment()).toMatchSnapshot();
	});
});
