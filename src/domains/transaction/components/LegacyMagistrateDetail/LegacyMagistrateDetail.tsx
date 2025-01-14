import { Modal } from "app/components/Modal";
import {
	TransactionExplorerLink,
	TransactionFee,
	TransactionSender,
	TransactionStatus,
	TransactionTimestamp,
} from "domains/transaction/components/TransactionDetail";
import { TransactionDetailProperties } from "domains/transaction/components/TransactionDetailModal/TransactionDetailModal.models";
import React, { useMemo } from "react";
import { useTranslation } from "react-i18next";

export const LegacyMagistrateDetail = ({ isOpen, transaction, onClose }: TransactionDetailProperties) => {
	const { t } = useTranslation();

	const wallet = useMemo(() => transaction.wallet(), [transaction]);

	return (
		<Modal title={t("TRANSACTION.TRANSACTION_TYPES.MAGISTRATE")} isOpen={isOpen} onClose={onClose}>
			<TransactionExplorerLink transaction={transaction} />

			<TransactionSender address={transaction.sender()} network={transaction.wallet().network()} border={false} />

			<TransactionFee currency={wallet.currency()} value={transaction.fee()} />

			<TransactionTimestamp timestamp={transaction.timestamp()} />

			<TransactionStatus transaction={transaction} />
		</Modal>
	);
};
