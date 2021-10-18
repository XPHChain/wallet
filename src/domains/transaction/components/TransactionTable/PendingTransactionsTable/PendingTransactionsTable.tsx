import { DTO } from "@payvo/profiles";
import { Table } from "app/components/Table";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";

import { ConfirmRemovePendingTransaction } from "../../ConfirmRemovePendingTransaction";
import { PendingTransferRow } from "../TransactionRow/PendingTransferRow";
import { SignedTransactionRow } from "../TransactionRow/SignedTransactionRow";
import { PendingTransaction, Properties } from "./PendingTransactionsTable.contracts";
import { usePendingTransactionTableColumns } from "./PendingTransactionsTable.helpers";

export const PendingTransactions = ({
	wallet,
	onClick,
	onRemove,
	onPendingTransactionClick,
	pendingTransactions,
	isCompact,
}: Properties) => {
	const { t } = useTranslation();
	const [pendingRemovalTransaction, setPendingRemovalTransaction] = useState<DTO.ExtendedSignedTransactionData>();

	const columns = usePendingTransactionTableColumns();

	const handleRemove = async (transaction: DTO.ExtendedSignedTransactionData) => {
		await wallet.coin().multiSignature().forgetById(transaction?.id());
		setPendingRemovalTransaction(undefined);
		onRemove?.(transaction);
	};

	return (
		<div data-testid="PendingTransactions" className="relative">
			<h2 className="mb-6 text-2xl font-bold">{t("WALLETS.PAGE_WALLET_DETAILS.PENDING_TRANSACTIONS")}</h2>

			<Table columns={columns} data={pendingTransactions}>
				{(transaction: PendingTransaction) => {
					if (transaction.isPendingTransfer) {
						return (
							<PendingTransferRow
								isCompact={isCompact}
								wallet={wallet}
								transaction={transaction.transaction as DTO.ExtendedConfirmedTransactionData}
								onRowClick={onPendingTransactionClick}
							/>
						);
					}

					return (
						<SignedTransactionRow
							isCompact={isCompact}
							transaction={transaction.transaction as DTO.ExtendedSignedTransactionData}
							wallet={wallet}
							onSign={onClick}
							onRowClick={onClick}
							onRemovePendingTransaction={setPendingRemovalTransaction}
						/>
					);
				}}
			</Table>

			<ConfirmRemovePendingTransaction
				isOpen={!!pendingRemovalTransaction}
				transaction={pendingRemovalTransaction}
				onClose={() => setPendingRemovalTransaction(undefined)}
				onRemove={handleRemove}
			/>
		</div>
	);
};
