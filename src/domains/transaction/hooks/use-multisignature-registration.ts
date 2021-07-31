import { Contracts as ProfileContracts } from "@payvo/profiles";
import { Services, Signatories } from "@payvo/sdk";
import { useLedgerContext } from "app/contexts";
import { Participant } from "domains/transaction/components/MultiSignatureRegistrationForm/components/AddParticipant/AddParticipant";
import { ExtendedSignedTransactionData } from "domains/transaction/pages/SendRegistration/SendRegistration.models";
import { withAbortPromise } from "domains/transaction/utils";
import { useRef } from "react";
import { assertString } from "utils/assertions";

interface SendMultisignatureProperties {
	wallet: ProfileContracts.IReadWriteWallet;
	participants: Participant[];
	minParticipants: number;
	fee: Services.TransactionFee;
	signatory: Signatories.Signatory;
}

interface AddSignatureProperties {
	transactionId: string;
	signatory: Signatories.Signatory;
	wallet: ProfileContracts.IReadWriteWallet;
}

export const useMultiSignatureRegistration = () => {
	const { abortConnectionRetry } = useLedgerContext();
	const abortReference = useRef(new AbortController());

	const signWithLedger = async (wallet: ProfileContracts.IReadWriteWallet) => {
		const prepareLedger = () =>
			wallet.signatory().ledger(wallet.data().get<string>(ProfileContracts.WalletData.DerivationPath)!);

		return withAbortPromise(abortReference.current?.signal, abortConnectionRetry)(prepareLedger());
	};

	const addSignature = async ({ transactionId, signatory, wallet }: AddSignatureProperties) => {
		await wallet.transaction().sync();

		if (wallet.isLedger()) {
			const ledgerSignatory = await signWithLedger(wallet);
			return wallet.transaction().addSignature(transactionId, ledgerSignatory);
		}

		return wallet.transaction().addSignature(transactionId, signatory);
	};

	const getPublicKey = (wallet: ProfileContracts.IReadWriteWallet) => {
		if (wallet.isLedger()) {
			const derivationPath = wallet.data().get(ProfileContracts.WalletData.DerivationPath);
			assertString(derivationPath);

			return wallet.ledger().getPublicKey(derivationPath);
		}

		return wallet.publicKey();
	};

	const sendMultiSignature = async ({
		wallet,
		participants,
		minParticipants,
		fee,
		signatory,
	}: SendMultisignatureProperties) => {
		// TODO: Handle ledger wallets of other participants without public keys (use derivation path)
		const restPublicKeys = participants
			.filter((participant) => participant.address !== wallet.address())
			.map((participant) => participant.publicKey);

		const senderPublicKey = await getPublicKey(wallet);
		assertString(senderPublicKey);

		const publicKeys = [senderPublicKey, ...restPublicKeys];
		await wallet.transaction().sync();

		const transaction: ExtendedSignedTransactionData = wallet.transaction().transaction(
			await wallet.transaction().signMultiSignature({
				data: {
					min: +minParticipants,
					publicKeys,
					senderPublicKey,
				},
				fee: +fee,
				signatory,
			}),
		);

		await wallet.transaction().broadcast(transaction.id());

		try {
			transaction.generatedAddress = (
				await wallet.coin().address().fromMultiSignature(minParticipants, publicKeys)
			).address;
		} catch {
			// We are using a coin that doesn't support multi-signature address derivation.
		}

		return transaction;
	};

	return { abortReference, addSignature, sendMultiSignature };
};