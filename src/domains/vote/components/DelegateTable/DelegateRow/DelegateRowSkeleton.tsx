import { Circle } from "app/components/Circle";
import { TableCell, TableRow } from "app/components/Table";
import { useRandomNumber } from "app/hooks";
import cn from "classnames";
import React from "react";
import Skeleton from "react-loading-skeleton";

interface DelegateRowSkeletonProperties {
	requiresStakeAmount?: boolean;
	isCompact?: boolean;
}

export const DelegateRowSkeleton = ({ requiresStakeAmount, isCompact }: DelegateRowSkeletonProperties) => {
	const nameWidth = useRandomNumber(120, 150);
	const circleSize = isCompact ? 20 : 44;

	return (
		<TableRow data-testid="DelegateRowSkeleton">
			<TableCell
				variant="start"
				innerClassName={cn({ "space-x-3": isCompact }, { "space-x-4": !isCompact })}
				isCompact={isCompact}
			>
				<Circle className="border-transparent" size={isCompact ? "xs" : "lg"}>
					<Skeleton className="align-top" circle height={circleSize} width={circleSize} />
				</Circle>

				<Skeleton height={16} width={nameWidth} />
			</TableCell>

			<TableCell className="w-24" innerClassName="justify-center" isCompact={isCompact}>
				<Skeleton height={16} width={22} />
			</TableCell>

			{requiresStakeAmount && (
				<TableCell className="w-68" innerClassName="justify-center" isCompact={isCompact}>
					<Skeleton height={isCompact ? 34 : 56} width={220} className="align-middle" />
				</TableCell>
			)}

			<TableCell variant="end" className="w-40" innerClassName="justify-end" isCompact={isCompact}>
				<Skeleton width={isCompact ? 80 : 100} height={isCompact ? 20 : 40} />
			</TableCell>
		</TableRow>
	);
};
