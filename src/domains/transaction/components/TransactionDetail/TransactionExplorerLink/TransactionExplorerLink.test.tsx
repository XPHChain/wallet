import React from "react";
import { render } from "utils/testing-library";

import { translations as transactionTranslations } from "../../../i18n";
import { TransactionExplorerLink } from "./TransactionExplorerLink";

describe("TransactionExplorerLink", () => {
	it("should render a transaction link", () => {
		const { container } = render(
			<TransactionExplorerLink
				// @ts-ignore
				transaction={{
					explorerLink: () => "transaction-link",
					id: () => "test-id",
				}}
			/>,
		);

		expect(container).toHaveTextContent(transactionTranslations.ID);
		expect(container).toMatchSnapshot();
	});
});
