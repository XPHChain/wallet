import React from "react";
import { fireEvent, render } from "utils/testing-library";

import { translations } from "../../i18n";
import { ApplicationError } from "./ApplicationError";

describe("ApplicationError", () => {
	it("should render", () => {
		const onResetErrorBoundary = jest.fn();
		const { asFragment, container, getByTestId } = render(
			<ApplicationError resetErrorBoundary={onResetErrorBoundary} />,
		);

		expect(container).toBeInTheDocument();
		expect(getByTestId("ApplicationError__text")).toHaveTextContent(translations.APPLICATION.TITLE);
		expect(getByTestId("ApplicationError__text")).toHaveTextContent(translations.APPLICATION.DESCRIPTION);

		fireEvent.click(getByTestId("ApplicationError__button--reload"));

		expect(onResetErrorBoundary).toHaveBeenCalled();
		expect(asFragment()).toMatchSnapshot();
	});
});
