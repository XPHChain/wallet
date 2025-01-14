import { Link } from "app/components/Link";
import React, { MouseEvent } from "react";
import { Trans, useTranslation } from "react-i18next";

export const SyncErrorMessage = ({
	failedNetworkNames,
	onRetry,
}: {
	failedNetworkNames: string[];
	onRetry?: () => void;
}) => {
	const { t } = useTranslation();

	return (
		<Trans
			i18nKey="COMMON.PROFILE_SYNC_FAILED"
			components={{
				NetworkNames: (
					<>
						{failedNetworkNames.map((networkName, index) => (
							<span key={index}>
								{failedNetworkNames.length > 1 && index === failedNetworkNames.length - 1 && (
									<span> {t("COMMON.AND")} </span>
								)}
								<strong>{networkName}</strong>
								{index < failedNetworkNames.length - 1 && ", "}
							</span>
						))}
					</>
				),
				RetryLink: (
					<>
						{[
							<Link
								key="1"
								data-testid="SyncErrorMessage__retry"
								onClick={(event: MouseEvent) => {
									event.preventDefault();
									event.stopPropagation();

									onRetry?.();
								}}
								to="/"
							>
								{t("COMMON.HERE")}
							</Link>,
						]}
					</>
				),
			}}
		/>
	);
};
