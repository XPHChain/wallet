import React from "react";
import { render } from "test-utils";

import { translations } from "../../i18n";
import { BlacklistPlugins } from "./BlacklistPlugins";

describe("BlacklistPlugins", () => {
	it("should not render if not open", () => {
		const { asFragment, getByTestId } = render(<BlacklistPlugins isOpen={false} />);

		expect(() => getByTestId("modal__inner")).toThrow(/Unable to find an element by/);
		expect(asFragment()).toMatchSnapshot();
	});

	it("should render a modal", () => {
		const { asFragment, getByTestId } = render(<BlacklistPlugins isOpen={true} />);

		expect(getByTestId("modal__inner")).toHaveTextContent(translations.MODAL_BLACKLIST_PLUGINS.TITLE);
		expect(getByTestId("modal__inner")).toHaveTextContent(translations.MODAL_BLACKLIST_PLUGINS.DESCRIPTION);
		expect(asFragment()).toMatchSnapshot();
	});
});