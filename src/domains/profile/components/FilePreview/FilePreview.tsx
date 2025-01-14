import { Icon } from "app/components/Icon";
import { Spinner } from "app/components/Spinner";
import { TruncateMiddle } from "app/components/TruncateMiddle";
import { ReadableFile } from "app/hooks/use-files";
import React from "react";

type FilePreviewVariant = "success" | "loading" | "danger";

interface FilePreviewProperties {
	file?: ReadableFile;
	variant?: FilePreviewVariant;
	useBorders?: boolean;
}

export const FilePreviewPlain = ({ file, variant }: { file: ReadableFile; variant?: FilePreviewVariant }) => {
	const fileTypeIcon: Record<string, string> = {
		".dwe": "ExtensionDwe",
		".json": "ExtensionJson",
	};

	return (
		<div className="flex justify-between items-center space-x-4">
			<div className="flex items-center space-x-4">
				<Icon name={fileTypeIcon[file.extension] || "File"} size="xl" />
				<div className="font-semibold">
					<TruncateMiddle text={file.name} maxChars={40} />
				</div>
			</div>

			{variant === "loading" && <Spinner size="md" />}

			{variant === "danger" && (
				<div className="flex justify-center items-center w-6 h-6 rounded-full text-theme-danger-500 bg-theme-danger-200">
					<Icon name="CrossSmall" size="sm" />
				</div>
			)}

			{variant === "success" && (
				<div className="flex justify-center items-center w-6 h-6 rounded-full text-theme-success-500 bg-theme-success-200">
					<Icon name="CheckmarkSmall" size="sm" />
				</div>
			)}
		</div>
	);
};

export const FilePreview = ({ file, useBorders = true, variant }: FilePreviewProperties) => {
	if (!file) {
		return <></>;
	}

	if (!useBorders) {
		return <FilePreviewPlain variant={variant} file={file} />;
	}

	return (
		<div className="p-4 rounded-lg border-2 border-theme-secondary-200 dark:border-theme-secondary-800">
			<FilePreviewPlain variant={variant} file={file} />
		</div>
	);
};
