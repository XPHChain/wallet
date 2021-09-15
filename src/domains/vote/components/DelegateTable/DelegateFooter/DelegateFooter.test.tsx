import { Contracts } from "@payvo/profiles";
import { ReadOnlyWallet } from "@payvo/profiles/distribution/read-only-wallet";
import { renderHook } from "@testing-library/react-hooks";
import { translations as voteTranslations } from "domains/vote/i18n";
import React from "react";
import { useTranslation } from "react-i18next";
import { data } from "tests/fixtures/coins/ark/devnet/delegates.json";
import { act, env, fireEvent, getDefaultProfileId, render, screen } from "utils/testing-library";

import { VoteDelegateProperties } from "../DelegateTable.models";
import { DelegateFooter } from "./DelegateFooter";

let wallet: Contracts.IReadWriteWallet;
let delegate: Contracts.IReadOnlyWallet;

describe("DelegateFooter", () => {
	beforeAll(() => {
		const profile = env.profiles().findById(getDefaultProfileId());
		wallet = profile.wallets().values()[0];

		delegate = new ReadOnlyWallet({
			address: data[0].address,
			explorerLink: "",
			governanceIdentifier: "address",
			isDelegate: true,
			isResignedDelegate: false,
			publicKey: data[0].publicKey,
			username: data[0].username,
		});
	});

	it("should render", () => {
		const { container, asFragment } = render(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(container).toBeTruthy();
		expect(asFragment()).toMatchSnapshot();
	});

	it("should show available balance if network requires vote amount", () => {
		const { rerender } = render(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(screen.queryByTestId("DelegateTable__available-balance")).not.toBeInTheDocument();

		const votesAmountMinimumMock = jest.spyOn(wallet.network(), "votesAmountMinimum").mockReturnValue(10);

		rerender(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(screen.getByTestId("DelegateTable__available-balance")).toBeInTheDocument();

		votesAmountMinimumMock.mockRestore();
	});

	it("should calculate remaining balance show it", () => {
		const {
			result: {
				current: { t },
			},
		} = renderHook(() => useTranslation());
		const votesAmountMinimumMock = jest.spyOn(wallet.network(), "votesAmountMinimum").mockReturnValue(10);

		render(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance() / 2}
				selectedVotes={[]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(screen.queryByTestId("DelegateTable__available-balance")).toBeInTheDocument();
		expect(
			screen.findByText(
				t("VOTE.DELEGATE_TABLE.VOTE_AMOUNT.AVAILABLE_TO_VOTE", {
					percent: 50,
				}),
			),
		).toBeTruthy();
		expect(screen.findByText(`16.87544901 ${wallet.network().coin()}`)).toBeTruthy();

		votesAmountMinimumMock.mockRestore();
	});

	it("should disable continue button with tooltip if user doesn't select a delegate", () => {
		const selectedDelegate: VoteDelegateProperties[] = [
			{
				amount: 0,
				delegateAddress: delegate.address(),
			},
		];

		const { rerender, baseElement } = render(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
				onContinue={jest.fn()}
			/>,
		);

		const continueWrapper = screen.getByTestId("DelegateTable__continue--wrapper");
		const continueButton = screen.getByTestId("DelegateTable__continue-button");

		expect(continueButton).toBeDisabled();

		act(() => {
			fireEvent.mouseEnter(continueWrapper);
		});

		expect(baseElement).toHaveTextContent(voteTranslations.DELEGATE_TABLE.TOOLTIP.SELECTED_DELEGATE);

		rerender(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={selectedDelegate}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(continueButton).not.toBeDisabled();

		rerender(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[]}
				selectedUnvotes={selectedDelegate}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(continueButton).not.toBeDisabled();

		act(() => {
			fireEvent.mouseEnter(continueWrapper);
		});

		expect(baseElement).not.toHaveTextContent(voteTranslations.DELEGATE_TABLE.TOOLTIP.SELECTED_DELEGATE);
	});

	it("should disable continue button with tooltip if there is at least 1 empty amount field when network requires vote amount", () => {
		const votesAmountMinimumMock = jest.spyOn(wallet.network(), "votesAmountMinimum").mockReturnValue(10);

		const selectedDelegate: VoteDelegateProperties[] = [
			{
				amount: 0,
				delegateAddress: delegate.address(),
			},
		];

		const { rerender, baseElement } = render(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={selectedDelegate}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
				onContinue={jest.fn()}
			/>,
		);

		const continueWrapper = screen.getByTestId("DelegateTable__continue--wrapper");
		const continueButton = screen.getByTestId("DelegateTable__continue-button");

		expect(continueButton).toBeDisabled();

		act(() => {
			fireEvent.mouseEnter(continueWrapper);
		});

		expect(baseElement).toHaveTextContent(voteTranslations.DELEGATE_TABLE.TOOLTIP.ZERO_AMOUNT);

		rerender(
			<DelegateFooter
				selectedWallet={wallet}
				availableBalance={wallet.balance()}
				selectedVotes={[
					{
						amount: 10,
						delegateAddress: delegate.address(),
					},
				]}
				selectedUnvotes={[]}
				maxVotes={wallet.network().maximumVotesPerTransaction()}
			/>,
		);

		expect(continueButton).not.toBeDisabled();

		votesAmountMinimumMock.mockRestore();
	});
});