import { Button } from "app/components/Button";
import { Icon } from "app/components/Icon";
import { Input } from "app/components/Input";
import cn from "classnames";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";

interface SearchBarProperties {
	placeholder?: string;
	className?: string;
	children?: React.ReactNode;
	onSearch?: any;
}

export const SearchBar = ({ placeholder, className, children, onSearch }: SearchBarProperties) => {
	const [query, setQuery] = useState("");

	const { t } = useTranslation();

	return (
		<div data-testid="SearchBar" className={cn("bg-theme-secondary-100 px-10 pt-8 pb-8", className)}>
			<div className="flex items-center py-6 px-10 rounded shadow-xl bg-theme-background">
				{children ? children : <Icon name="MagnifyingGlass" className="mr-8 w-4 text-theme-secondary-300" />}

				<div className="flex-1 pl-4 mr-4 border-l border-theme-secondary-300 dark:border-theme-secondary-800">
					<Input
						placeholder={placeholder || t("COMMON.SEARCH_BAR.PLACEHOLDER")}
						onChange={(event) => setQuery((event.target as HTMLInputElement).value)}
						noBorder
						noShadow
					/>
				</div>

				<Button data-testid="SearchBar__button" onClick={() => onSearch(query)} className="my-1">
					<span className="px-2 text-md">{t("COMMON.SEARCH_BAR.FIND_IT")}</span>
				</Button>
			</div>
		</div>
	);
};
