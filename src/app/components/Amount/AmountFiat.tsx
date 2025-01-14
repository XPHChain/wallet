import cn from "classnames";
import React from "react";

import { AmountProperties } from "./Amount.contracts";
import { formatFiat, formatWithSign } from "./Amount.helpers";

const AmountFiat: React.FC<AmountProperties> = ({
	ticker,
	value,
	isNegative = false,
	showSign,
	className,
}: AmountProperties) => {
	let formattedAmount = formatFiat({ ticker, value });

	if (showSign) {
		formattedAmount = formatWithSign(formattedAmount, isNegative);
	}

	return (
		<span data-testid="AmountFiat" className={cn("whitespace-nowrap", className)}>
			{formattedAmount}
		</span>
	);
};

export { AmountFiat };
