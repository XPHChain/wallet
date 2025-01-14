import { Helpers } from "@payvo/profiles";
import cn from "classnames";
import React from "react";
import tw, { styled } from "twin.macro";
import { Size } from "types";

interface Properties {
	address?: string;
	className?: string;
	shadowClassName?: string;
	highlight?: boolean;
	noShadow?: boolean;
	size?: Size;
	children?: React.ReactNode;
}

const AvatarWrapper = styled.div<Properties>`
	${tw`transition-all duration-100 relative inline-flex items-center justify-center align-middle rounded-full`}

	${({ size }) => {
		switch (size) {
			case "xs":
				return tw`w-5 h-5 text-sm`;
			case "sm":
				return tw`w-8 h-8 text-sm`;
			case "lg":
				return tw`w-11 h-11 text-sm`;
			case "xl":
				return tw`w-16 h-16 text-xl`;
			default:
				return tw`w-10 h-10`;
		}
	}}

	${({ noShadow, shadowClassName }) => {
		if (noShadow) {
			return;
		}

		if (shadowClassName) {
			return tw`ring-6`;
		}

		return tw`ring-6 ring-theme-background`;
	}}
`;

export const Avatar = ({
	address = "",
	className,
	highlight,
	noShadow,
	shadowClassName,
	size,
	children,
}: Properties) => {
	const svg = React.useMemo(() => (address ? Helpers.Avatar.make(address) : undefined), [address]);

	return (
		<AvatarWrapper
			data-testid="Avatar"
			size={size}
			noShadow={!!noShadow}
			className={cn(className, shadowClassName, "flex-shrink-0")}
			shadowClassName={shadowClassName}
		>
			<div
				className={cn(
					"w-full h-full inline-flex items-center justify-center overflow-hidden align-middle rounded-full",
					{ "ring-2 ring-theme-primary-600": highlight },
				)}
			>
				{svg && <img alt={address} title={address} src={`data:image/svg+xml;utf8,${svg}`} />}
				{children}
			</div>
		</AvatarWrapper>
	);
};
