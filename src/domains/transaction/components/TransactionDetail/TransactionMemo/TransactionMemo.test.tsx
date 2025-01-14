import React from "react";
import { render } from "utils/testing-library";

import { translations as transactionTranslations } from "../../../i18n";
import { TransactionMemo } from "./TransactionMemo";

describe("TransactionMemo", () => {
	it("should render", () => {
		const memo = "test memo";

		const { container } = render(<TransactionMemo memo={memo} />);

		expect(container).toHaveTextContent(transactionTranslations.MEMO);
		expect(container).toHaveTextContent(memo);

		expect(container).toMatchSnapshot();
	});
});
