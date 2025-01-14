/* eslint-disable @typescript-eslint/require-await */
import { BIP39 } from "@payvo/cryptography";
import { Contracts } from "@payvo/profiles";
import { act } from "@testing-library/react-hooks";
import { translations as walletTranslations } from "domains/wallet/i18n";
import { createMemoryHistory } from "history";
import React from "react";
import { Route } from "react-router-dom";
import { env, fireEvent, getDefaultProfileId, render, screen, waitFor } from "utils/testing-library";

import { CreateWallet } from "./CreateWallet";

jest.setTimeout(30_000);

let profile: Contracts.IProfile;
let bip39GenerateMock: any;

const fixtureProfileId = getDefaultProfileId();
const passphrase = "power return attend drink piece found tragic fire liar page disease combine";

describe("CreateWallet", () => {
	beforeAll(() => {
		bip39GenerateMock = jest.spyOn(BIP39, "generate").mockReturnValue(passphrase);
	});

	afterAll(() => {
		bip39GenerateMock.mockRestore();
	});

	beforeEach(() => {
		profile = env.profiles().findById(fixtureProfileId);

		for (const wallet of profile.wallets().values()) {
			profile.wallets().forget(wallet.id());
		}

		bip39GenerateMock = jest.spyOn(BIP39, "generate").mockReturnValue(passphrase);
	});

	afterEach(() => {
		bip39GenerateMock.mockRestore();
	});

	it("should create a wallet", async () => {
		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { queryAllByText, getByTestId, getByText, asFragment, findByTestId } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL],
			},
		);

		await findByTestId("NetworkStep");

		expect(asFragment()).toMatchSnapshot();

		const selectNetworkInput = getByTestId("SelectNetworkInput__input");
		const continueButton = getByTestId("CreateWallet__continue-button");
		const backButton = getByTestId("CreateWallet__back-button");

		const historySpy = jest.spyOn(history, "push").mockImplementation();

		expect(backButton).not.toHaveAttribute("disabled");

		fireEvent.click(backButton);

		expect(historySpy).toHaveBeenCalledWith(`/profiles/${fixtureProfileId}/dashboard`);

		fireEvent.change(selectNetworkInput, { target: { value: "ARK Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });
		await waitFor(() => expect(selectNetworkInput).toHaveValue("ARK Devnet"));

		expect(continueButton).not.toHaveAttribute("disabled");

		fireEvent.change(selectNetworkInput, { target: { value: "" } });
		await waitFor(() => expect(selectNetworkInput).toHaveValue(""));

		expect(continueButton).toHaveAttribute("disabled");

		fireEvent.change(selectNetworkInput, { target: { value: "ARK Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });
		await waitFor(() => expect(selectNetworkInput).toHaveValue("ARK Devnet"));

		expect(continueButton).not.toHaveAttribute("disabled");

		fireEvent.click(continueButton);

		await waitFor(() => expect(profile.wallets().values()).toHaveLength(0));

		await findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(backButton);
		await findByTestId("NetworkStep");

		fireEvent.click(continueButton);
		await findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(continueButton);
		await findByTestId("CreateWallet__ConfirmPassphraseStep");

		fireEvent.click(backButton);

		await findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(continueButton);
		await findByTestId("CreateWallet__ConfirmPassphraseStep");

		const walletMnemonic = passphrase.split(" ");
		for (let index = 0; index < 3; index++) {
			const wordNumber = Number.parseInt(getByText(/Select the/).innerHTML.replace(/Select the/, ""));

			fireEvent.click(getByText(walletMnemonic[wordNumber - 1]));

			if (index < 2) {
				await waitFor(() => expect(queryAllByText(/The #(\d+) word/).length === 2 - index));
			}
		}
		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.click(continueButton);

		await findByTestId("EncryptPassword");

		expect(profile.wallets().values()).toHaveLength(0);

		fireEvent.click(getByTestId("CreateWallet__skip-button"));

		await findByTestId("CreateWallet__SuccessStep");

		expect(profile.wallets().values()).toHaveLength(1);

		fireEvent.click(getByTestId("CreateWallet__edit-alias"));

		await findByTestId("modal__inner");

		fireEvent.input(getByTestId("UpdateWalletName__input"), { target: { value: "test alias" } });

		await waitFor(() => expect(getByTestId("UpdateWalletName__submit")).not.toBeDisabled());

		fireEvent.click(getByTestId("UpdateWalletName__submit"));

		await waitFor(() => expect(() => getByTestId("modal__inner")).toThrow(/Unable to find an element by/));

		fireEvent.click(getByTestId("CreateWallet__finish-button"));

		const wallet = profile.wallets().first();

		expect(wallet.alias()).toBe("test alias");

		await waitFor(() =>
			expect(historySpy).toHaveBeenCalledWith(`/profiles/${profile.id()}/wallets/${wallet.id()}`),
		);

		expect(asFragment()).toMatchSnapshot();

		historySpy.mockRestore();
	});

	it("should create a wallet with encryption", async () => {
		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { asFragment } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL],
			},
		);

		await screen.findByTestId("NetworkStep");

		expect(asFragment()).toMatchSnapshot();

		const selectNetworkInput = screen.getByTestId("SelectNetworkInput__input");
		const continueButton = screen.getByTestId("CreateWallet__continue-button");
		const backButton = screen.getByTestId("CreateWallet__back-button");

		const historySpy = jest.spyOn(history, "push").mockImplementation();

		expect(backButton).not.toHaveAttribute("disabled");

		fireEvent.click(backButton);

		expect(historySpy).toHaveBeenCalledWith(`/profiles/${fixtureProfileId}/dashboard`);

		fireEvent.change(selectNetworkInput, { target: { value: "ARK Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });
		await waitFor(() => expect(selectNetworkInput).toHaveValue("ARK Devnet"));

		expect(continueButton).not.toHaveAttribute("disabled");

		fireEvent.change(selectNetworkInput, { target: { value: "" } });
		await waitFor(() => expect(selectNetworkInput).toHaveValue(""));

		expect(continueButton).toHaveAttribute("disabled");

		fireEvent.change(selectNetworkInput, { target: { value: "ARK Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });
		await waitFor(() => expect(selectNetworkInput).toHaveValue("ARK Devnet"));

		expect(continueButton).not.toHaveAttribute("disabled");

		fireEvent.click(continueButton);

		await waitFor(() => expect(profile.wallets().values()).toHaveLength(0));

		await screen.findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(backButton);
		await screen.findByTestId("NetworkStep");

		fireEvent.click(continueButton);
		await screen.findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(continueButton);
		await screen.findByTestId("CreateWallet__ConfirmPassphraseStep");

		fireEvent.click(backButton);

		await screen.findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(continueButton);
		await screen.findByTestId("CreateWallet__ConfirmPassphraseStep");

		const walletMnemonic = passphrase.split(" ");
		for (let index = 0; index < 3; index++) {
			const wordNumber = Number.parseInt(screen.getByText(/Select the/).innerHTML.replace(/Select the/, ""));

			fireEvent.click(screen.getByText(walletMnemonic[wordNumber - 1]));

			if (index < 2) {
				await waitFor(() => expect(screen.queryAllByText(/The #(\d+) word/).length === 2 - index));
			}
		}
		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.click(continueButton);

		await screen.findByTestId("EncryptPassword");

		expect(screen.getAllByTestId("InputPassword")).toHaveLength(2);

		fireEvent.input(screen.getAllByTestId("InputPassword")[0], {
			target: {
				value: "S3cUrePa$sword",
			},
		});

		fireEvent.input(screen.getAllByTestId("InputPassword")[1], {
			target: {
				value: "S3cUrePa$sword",
			},
		});

		const continueEncryptionButton = screen.getByTestId("CreateWallet__continue-encryption-button");

		await waitFor(() => expect(continueEncryptionButton).not.toBeDisabled());

		fireEvent.click(continueEncryptionButton);

		await screen.findByTestId("CreateWallet__SuccessStep");

		expect(profile.wallets().values()).toHaveLength(1);

		fireEvent.click(screen.getByTestId("CreateWallet__finish-button"));

		const wallet = profile.wallets().first();

		expect(wallet.alias()).toBe("ARK Devnet #1");

		await waitFor(() =>
			expect(historySpy).toHaveBeenCalledWith(`/profiles/${profile.id()}/wallets/${wallet.id()}`),
		);

		expect(asFragment()).toMatchSnapshot();

		historySpy.mockRestore();
	});

	it("should not have a pending wallet if leaving on step 1", async () => {
		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { asFragment, findByTestId } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL, "/"],
			},
		);
		await findByTestId("NetworkStep");

		history.push("/");
		await waitFor(() => expect(profile.wallets().values()).toHaveLength(0));

		expect(asFragment()).toMatchSnapshot();
	});

	it("should remove pending wallet if not submitted", async () => {
		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { getByTestId, asFragment, findByTestId } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL, "/"],
			},
		);
		await findByTestId("NetworkStep");

		const selectNetworkInput = getByTestId("SelectNetworkInput__input");
		const continueButton = getByTestId("CreateWallet__continue-button");

		expect(asFragment()).toMatchSnapshot();

		fireEvent.change(selectNetworkInput, { target: { value: "Ark Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });

		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.click(continueButton);

		await findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(getByTestId("CreateWallet__back-button"));

		await findByTestId("NetworkStep");

		fireEvent.click(continueButton);

		await findByTestId("CreateWallet__WalletOverviewStep");

		act(() => {
			history.push("/");
		});
		await waitFor(() => expect(profile.wallets().values()).toHaveLength(0));

		expect(asFragment()).toMatchSnapshot();
	});

	it("should show an error message if wallet generation failed", async () => {
		bip39GenerateMock.mockRestore();
		bip39GenerateMock = jest.spyOn(BIP39, "generate").mockImplementation(() => {
			throw new Error("test");
		});

		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { asFragment } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL, "/"],
			},
		);

		await screen.findByTestId("NetworkStep");

		const selectNetworkInput = screen.getByTestId("SelectNetworkInput__input");

		fireEvent.change(selectNetworkInput, { target: { value: "ARK D" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });

		expect(selectNetworkInput).toHaveValue("ARK Devnet");

		const continueButton = screen.getByTestId("CreateWallet__continue-button");

		await waitFor(() => {
			expect(continueButton).not.toBeDisabled();
		});

		fireEvent.click(continueButton);

		await screen.findByText(walletTranslations.PAGE_CREATE_WALLET.NETWORK_STEP.GENERATION_ERROR);

		expect(asFragment()).toMatchSnapshot();

		bip39GenerateMock.mockRestore();
	});

	it("should show an error message for duplicate name", async () => {
		const wallet = await profile.walletFactory().fromAddress({
			address: "D8rr7B1d6TL6pf14LgMz4sKp1VBMs6YUYD",
			coin: "ARK",
			network: "ark.devnet",
		});

		profile.wallets().push(wallet);
		wallet.settings().set(Contracts.WalletSetting.Alias, "Test");

		const history = createMemoryHistory();
		const createURL = `/profiles/${fixtureProfileId}/wallets/create`;
		history.push(createURL);

		const { queryAllByText, getByTestId, getByText, asFragment, findByTestId } = render(
			<Route path="/profiles/:profileId/wallets/create">
				<CreateWallet />
			</Route>,
			{
				history,
				routes: [createURL],
			},
		);

		await findByTestId("NetworkStep");

		expect(asFragment()).toMatchSnapshot();

		const selectNetworkInput = getByTestId("SelectNetworkInput__input");
		const continueButton = getByTestId("CreateWallet__continue-button");

		fireEvent.change(selectNetworkInput, { target: { value: "Ark Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });

		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.change(selectNetworkInput, { target: { value: "" } });
		await waitFor(() => expect(continueButton).toHaveAttribute("disabled"));

		fireEvent.change(selectNetworkInput, { target: { value: "Ark Dev" } });
		fireEvent.keyDown(selectNetworkInput, { code: 13, key: "Enter" });

		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.click(continueButton);

		await findByTestId("CreateWallet__WalletOverviewStep");

		fireEvent.click(continueButton);

		await findByTestId("CreateWallet__ConfirmPassphraseStep");

		const walletMnemonic = passphrase.split(" ");
		for (let index = 0; index < 3; index++) {
			const wordNumber = Number.parseInt(getByText(/Select the/).innerHTML.replace(/Select the/, ""));

			fireEvent.click(getByText(walletMnemonic[wordNumber - 1]));

			if (index < 2) {
				await waitFor(() => expect(queryAllByText(/The #(\d+) word/).length === 2 - index));
			}
		}
		await waitFor(() => expect(continueButton).not.toHaveAttribute("disabled"));

		fireEvent.click(continueButton);

		await findByTestId("EncryptPassword");

		fireEvent.click(getByTestId("CreateWallet__skip-button"));

		await findByTestId("CreateWallet__SuccessStep");

		fireEvent.click(getByTestId("CreateWallet__edit-alias"));

		await findByTestId("modal__inner");

		fireEvent.input(getByTestId("UpdateWalletName__input"), { target: { value: "Test" } });

		await waitFor(() => expect(getByTestId("UpdateWalletName__submit")).toBeDisabled());

		fireEvent.click(getByTestId("UpdateWalletName__cancel"));

		await waitFor(() => expect(() => getByTestId("modal__inner")).toThrow(/Unable to find an element by/));
	});
});
