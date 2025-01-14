import { Circle } from "app/components/Circle";
import tw, { styled } from "twin.macro";

const disabledColor = tw`text-theme-secondary-500 dark:text-theme-secondary-700`;

export const LabelWrapper = styled.div`
	${tw`text-sm leading-tight`};
	${disabledColor};
`;

export const TextWrapper = styled.div<{ disabled?: boolean }>`
	${tw`text-lg leading-tight`};

	${({ disabled }) => {
		if (disabled) {
			return disabledColor;
		}

		return tw`text-theme-text`;
	}}
`;

export const StyledCircle = styled(Circle)<{ disabled?: boolean }>`
	${tw`bg-theme-background`};

	${({ disabled }) => {
		if (disabled) {
			return [tw`border-theme-secondary-500 dark:border-theme-secondary-700`, disabledColor];
		}

		return tw`border-theme-secondary-900 text-theme-secondary-900 dark:(border-theme-secondary-600 text-theme-secondary-600)`;
	}}
`;
