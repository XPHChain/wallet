export interface RecipientProperties {
	id: string;
	address: string;
	alias?: string;
	network?: string;
	avatar: string;
	type: string;
}

export interface RecipientListItemProperties {
	index: number;
	recipient: RecipientProperties;
	onAction: (address: string) => void;
	selectedAddress?: string;
}

export interface SearchRecipientProperties {
	title?: string;
	description?: string;
	isOpen: boolean;
	onClose?: () => void;
	onAction: (address: string) => void;
	recipients: RecipientProperties[];
	selectedAddress?: string;
}
