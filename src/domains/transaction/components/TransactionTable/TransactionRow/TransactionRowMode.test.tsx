import React from "react";
import { render, screen } from "testing-library";
import { TransactionFixture } from "tests/fixtures/transactions";

import { BaseTransactionRowMode, TransactionRowMode } from "./TransactionRowMode";

describe("TransactionRowMode", () => {
	it("should render sent icon", () => {
		render(<TransactionRowMode transaction={TransactionFixture} />);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("sent.svg");
		expect(screen.getByTestId("Avatar")).toBeTruthy();
	});

	it("should render sent icon", () => {
		render(<TransactionRowMode transaction={{ ...TransactionFixture, isSent: () => true }} />);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("sent.svg");
	});

	it("should render received icon", () => {
		render(<TransactionRowMode transaction={{ ...TransactionFixture, isSent: () => false }} />);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("received.svg");
	});

	it("should render return icon", () => {
		const { rerender } = render(
			<TransactionRowMode transaction={{ ...TransactionFixture, isReturn: () => true }} />,
		);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("return.svg");

		rerender(
			<TransactionRowMode
				transaction={{ ...TransactionFixture, isReturn: () => true, type: () => "multiPayment" }}
			/>,
		);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("return.svg");
	});
});

describe("BaseTransactionRowMode", () => {
	it("should render", () => {
		render(<BaseTransactionRowMode transaction={TransactionFixture} />);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("received.svg");
	});

	it("should render compact", () => {
		render(<BaseTransactionRowMode transaction={TransactionFixture} isCompact />);

		expect(screen.getByTestId("TransactionRowMode")).toHaveTextContent("received.svg");
	});
});
