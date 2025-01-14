import { images } from "app/assets/images";
import { SvgCollection } from "app/assets/svg";
import { Link } from "app/components/Link";
import FTXBanner from "domains/news/images/ftx-banner.png";
import React from "react";
import { useTranslation } from "react-i18next";

const { DownloadAppStoreButton, DownloadGooglePlayButton } = images.news.common;

export const FTXAd = () => {
	const { t } = useTranslation();

	return (
		<div className="relative">
			<div className="flex absolute top-0 right-4 text-center rounded-b-xl bg-theme-primary-100 dark:bg-theme-secondary-800">
				<span className="px-2 pt-1 pb-2 text-xs font-semibold text-theme-primary-600">{t("NEWS.AD")}</span>
			</div>

			<img
				src={FTXBanner}
				className="w-full rounded-lg border-2 border-theme-primary-100 dark:border-theme-secondary-800"
				alt="FTX Banner"
			/>

			<div className="absolute left-10 top-16">
				<div className="flex flex-col items-start space-y-5 text-white">
					<Link to="https://ftx.com/" showExternalIcon={false} isExternal>
						<SvgCollection.FTX className="-mx-8 text-white" width={238} height={47} />
					</Link>
					<p className="w-3/4 text-lg font-medium">
						The world&apos;s most popular Bitcoin &amp; cryptocurrency portfolio tracker. 100% free.
					</p>
				</div>

				<div className="flex mt-12 space-x-2">
					<Link
						to="https://itunes.apple.com/us/app/blockfolio-bitcoin-altcoin/id1095564685?mt=8"
						showExternalIcon={false}
						isExternal
					>
						<DownloadAppStoreButton className="w-32 h-10 b-0" />
					</Link>

					<Link
						to="https://play.google.com/store/apps/details?id=com.blockfolio.blockfolio&amp;hl=en_US"
						showExternalIcon={false}
						isExternal
					>
						<DownloadGooglePlayButton className="w-32 h-10" />
					</Link>
				</div>
			</div>
		</div>
	);
};
