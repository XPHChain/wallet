import { Skeleton } from "app/components/Skeleton";
import { TableCell, TableRow } from "app/components/Table";
import { useRandomNumber } from "app/hooks";
import React from "react";

export const NotificationTransactionSkeletonRow: React.FC = () => {
	const recipientWidth = useRandomNumber(120, 150);
	const amountWidth = useRandomNumber(100, 130);

	return (
		<TableRow>
			<TableCell variant="start" innerClassName="space-x-3" isCompact>
				<div className="flex items-center space-x-2">
					<Skeleton circle height={20} width={20} />
					<Skeleton circle height={20} width={20} />
				</div>

				<Skeleton height={16} width={recipientWidth} />
			</TableCell>

			<TableCell variant="end" innerClassName="justify-end" isCompact>
				<span className="flex items-center px-2 space-x-1 h-7 rounded border border-theme-secondary-300 dark:border-theme-secondary-800">
					<Skeleton height={16} width={amountWidth} />
					<Skeleton height={16} width={35} />
				</span>
			</TableCell>
		</TableRow>
	);
};
