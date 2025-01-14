import { DateTime } from "@payvo/intl";
import { BigNumber } from "@payvo/helpers";

const wallet = {
	address: () => "D8rr7B1d6TL6pf14LgMz4sKp1VBMs6YUYD",
	alias: () => "Test Wallet",
	currency: () => "ARK",
	exchangeCurrency: () => "BTC",
	isDelegate: () => true,
	isLedger: () => false,
	isResignedDelegate: () => false,
	transaction: () => ({
		canBeSigned: () => false,
		isAwaitingOurSignature: () => false,
	}),
	network: () => ({
		id: () => "ark.devnet",
		isTest: () => true,
	}),
};

export const TransactionFixture = {
	id: () => "ea63bf9a4b3eaf75a1dfff721967c45dce64eb7facf1aef29461868681b5c79b",
	blockId: () => "71fd1a494ded5430586f4dd1c79c3ac77bf38120e868c8f8980972b8075d67e9",
	type: () => "transfer",
	timestamp: () => DateTime.fromUnix(1596213281),
	confirmations: () => BigNumber.make(10),
	votes: () => ["034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"],
	unvotes: () => ["034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"],
	sender: () => "D8rr7B1d6TL6pf14LgMz4sKp1VBMs6YUYD",
	recipient: () => "D8rr7B1d6TL6pf14LgMz4sKp1VBMs6YUYD",
	recipients: () => [],
	amount: () => 100,
	convertedAmount: () => 0,
	fee: () => 21,
	convertedFee: () => 0,
	memo: () => "Test",
	asset: () => ({ a: "b" }),
	isConfirmed: () => false,
	isSent: () => true,
	isReceived: () => false,
	isReturn: () => false,
	isTransfer: () => true,
	isSecondSignature: () => false,
	isMultiSignatureRegistration: () => false,
	usesMultiSignature: () => false,
	isDelegateRegistration: () => false,
	isDelegateResignation: () => false,
	isVoteCombination: () => false,
	isVote: () => false,
	isUnvote: () => false,
	isIpfs: () => false,
	isMultiPayment: () => false,
	isHtlcLock: () => false,
	isHtlcClaim: () => false,
	isHtlcRefund: () => false,
	isMagistrate: () => false,
	toObject: () => ({ a: "b" }),
	hasPassed: () => true,
	hasFailed: () => false,
	getMeta: () => "",
	setMeta: () => "",
	// IPFS Type
	hash: () => "QmPRqPTEEwx95WNcSsk6YQk7aGW9hoZbTF9zE92dBj9H68",
	// @ts-ignore
	explorerLink: () =>
		"https://explorer.ark.io/transaction/ee4175091d9f4dacf5fed213711c3e0e4cc371e37afa7bce0429d09bcf3ecefe",
	explorerLinkForBlock: () =>
		"https://explorer.ark.io/blocks/71fd1a494ded5430586f4dd1c79c3ac77bf38120e868c8f8980972b8075d67e9",
	total: () => 121,
	convertedTotal: () => 0,
	wallet: () => wallet,
	coin: () => undefined,
	data: () => {
		return {
			data: () => {},
		};
	},
	get: () => "",
};
