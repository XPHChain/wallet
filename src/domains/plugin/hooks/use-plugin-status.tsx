import { useTranslation } from "react-i18next";

interface Properties {
	isEnabled?: boolean;
	isInstalled?: boolean;
}

const usePluginStatus = () => {
	const { t } = useTranslation();

	const renderPluginStatus = ({ isEnabled, isInstalled }: Properties) => {
		if (!isInstalled) {
			return t("PLUGINS.STATUS.NOT_INSTALLED");
		}

		if (isEnabled) {
			return t("PLUGINS.STATUS.ENABLED");
		}

		return t("PLUGINS.STATUS.DISABLED");
	};

	return { renderPluginStatus };
};

export { usePluginStatus };
