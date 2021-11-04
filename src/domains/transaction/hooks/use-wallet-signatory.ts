import { Contracts as ProfileContracts } from "@payvo/profiles";
import { Services, Signatories } from "@payvo/sdk";
import { useCallback } from "react";
import { assertString } from "utils/assertions";

export interface SignInput {
	encryptionPassword?: string;
	mnemonic?: string;
	secondMnemonic?: string;
	secret?: string;
	secondSecret?: string;
	wif?: string;
	privateKey?: string;
}

// @TODO: extract this into the SDK/Profiles
export const useWalletSignatory = (
	wallet: ProfileContracts.IReadWriteWallet,
): {
	sign: ({
		encryptionPassword,
		mnemonic,
		secondMnemonic,
		secret,
		secondSecret,
		wif,
		privateKey,
	}: SignInput) => Promise<Signatories.Signatory>;
} => ({
	sign: useCallback(
		async ({ encryptionPassword, mnemonic, secondMnemonic, secret, secondSecret, wif, privateKey }: SignInput) => {
			if (mnemonic && secondMnemonic) {
				return wallet.signatory().confirmationMnemonic(mnemonic, secondMnemonic);
			}

			if (mnemonic) {
				return wallet.signatory().mnemonic(mnemonic);
			}

			if (encryptionPassword) {
				if (wallet.isSecondSignature()) {
					if (wallet.actsWithSecretWithEncryption()) {
						return wallet
							.signatory()
							.confirmationSecret(
								wallet.signingKey().get(encryptionPassword),
								wallet.confirmKey().get(encryptionPassword),
							);
					}

					return wallet
						.signatory()
						.confirmationMnemonic(
							wallet.signingKey().get(encryptionPassword),
							wallet.confirmKey().get(encryptionPassword),
						);
				}

				if (wallet.actsWithSecretWithEncryption()) {
					return wallet.signatory().secret(wallet.signingKey().get(encryptionPassword));
				}

				return wallet.signatory().mnemonic(wallet.signingKey().get(encryptionPassword));
			}

			if (wallet.isMultiSignature()) {
				return wallet.signatory().multiSignature(wallet.multiSignature().all() as Services.MultiSignatureAsset);
			}

			if (wallet.isLedger()) {
				const derivationPath = wallet.data().get(ProfileContracts.WalletData.DerivationPath);

				assertString(derivationPath);

				return wallet.signatory().ledger(derivationPath);
			}

			if (wif) {
				return wallet.signatory().wif(wif);
			}

			if (privateKey) {
				return wallet.signatory().privateKey(privateKey);
			}

			if (secret && secondSecret) {
				return wallet.signatory().confirmationSecret(secret, secondSecret);
			}

			if (secret) {
				return wallet.signatory().secret(secret);
			}

			throw new Error("Signing failed. No mnemonic or encryption password provided");
		},
		[wallet],
	),
});
