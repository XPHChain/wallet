import { Contracts } from "@payvo/profiles";
import { Alert } from "app/components/Alert";
import { Page, Section } from "app/components/Layout";
import { useEnvironmentContext } from "app/contexts";
import { useActiveProfile, useActiveWallet, useProfileJobs, useProfileUtils } from "app/hooks";
import { DelegateTable } from "domains/vote/components/DelegateTable";
import { VotesEmpty } from "domains/vote/components/VotesEmpty";
import { VotesHeader } from "domains/vote/components/VotesHeader";
import { VotingWallets } from "domains/vote/components/VotingWallets/VotingWallets";
import { useDelegates } from "domains/vote/hooks/use-delegates";
import { useVoteActions } from "domains/vote/hooks/use-vote-actions";
import { useVoteFilters } from "domains/vote/hooks/use-vote-filters";
import { useVoteQueryParameters } from "domains/vote/hooks/use-vote-query-parameters";
import React, { useEffect, useState } from "react";
import { Trans } from "react-i18next";
import { useHistory, useParams } from "react-router-dom";
import { assertWallet } from "utils/assertions";

export const Votes = () => {
	const history = useHistory();
	const { walletId: hasWalletId } = useParams<{ walletId: string }>();
	const { env } = useEnvironmentContext();

	const activeProfile = useActiveProfile();
	const activeWallet = useActiveWallet();
	const [selectedWallet, setSelectedWallet] = useState<Contracts.IReadWriteWallet>(activeWallet);

	const { getErroredNetworks } = useProfileUtils(env);
	const { syncProfileWallets } = useProfileJobs(activeProfile);

	const { filter, voteDelegates, unvoteDelegates } = useVoteQueryParameters();

	const {
		filterProperties,
		isFilterChanged,
		filteredWalletsByCoin,
		hasEmptyResults,
		hasWallets,
		voteFilter,
		setVoteFilter,
		selectedAddress,
		setSelectedAddress,
		selectedNetwork,
		setSelectedNetwork,
		searchQuery,
		setSearchQuery,
		maxVotes,
		setMaxVotes,
	} = useVoteFilters({
		filter,
		hasWalletId: !!hasWalletId,
		profile: activeProfile,
		wallet: activeWallet,
	});

	const {
		isLoadingDelegates,
		fetchDelegates,
		currentVotes,
		filteredDelegates,
		fetchVotes,
		votes,
		resignedDelegateVotes,
	} = useDelegates({
		env,
		profile: activeProfile,
		searchQuery,
		voteFilter,
	});

	const { navigateToSendVote } = useVoteActions({
		hasWalletId: !!hasWalletId,
		profile: activeProfile,
		selectedAddress,
		selectedNetwork,
		wallet: activeWallet,
	});

	useEffect(() => {
		if (selectedAddress && selectedNetwork) {
			fetchVotes(selectedAddress, selectedNetwork);
		}
	}, [fetchVotes, selectedAddress, selectedNetwork]);

	useEffect(() => {
		if (hasWalletId) {
			fetchDelegates(activeWallet);
		}
	}, [activeWallet, fetchDelegates, hasWalletId]);

	useEffect(() => {
		if (votes?.length === 0) {
			setVoteFilter("all");
		}
	}, [votes, setVoteFilter]);

	useEffect(() => {
		const { hasErroredNetworks } = getErroredNetworks(activeProfile);
		if (!hasErroredNetworks) {
			return;
		}

		syncProfileWallets(true);
	}, []); // eslint-disable-line react-hooks/exhaustive-deps

	const handleSelectAddress = (address: string, network: string) => {
		const wallet = activeProfile.wallets().findByAddressWithNetwork(address, network);

		assertWallet(wallet);

		setSearchQuery("");
		setSelectedAddress(address);
		setSelectedNetwork(network);
		setSelectedWallet(wallet);
		setMaxVotes(wallet?.network().maximumVotesPerWallet());

		fetchDelegates(wallet);
	};

	const hasSelectedAddress = !!selectedAddress;

	const useCompactTables = !activeProfile.appearance().get("useExpandedTables");

	return (
		<Page profile={activeProfile}>
			<Section border>
				<VotesHeader
					profile={activeProfile}
					setSearchQuery={setSearchQuery}
					selectedAddress={selectedAddress}
					isFilterChanged={isFilterChanged}
					filterProperties={filterProperties}
					totalCurrentVotes={currentVotes?.length || 0}
					selectedFilter={voteFilter}
					setSelectedFilter={setVoteFilter}
				/>
			</Section>

			{!hasWallets && (
				<Section>
					<VotesEmpty
						onCreateWallet={() => history.push(`/profiles/${activeProfile.id()}/wallets/create`)}
						onImportWallet={() => history.push(`/profiles/${activeProfile.id()}/wallets/import`)}
					/>
				</Section>
			)}

			{hasWallets && !hasSelectedAddress && (
				<VotingWallets
					showEmptyResults={hasEmptyResults}
					walletsByCoin={filteredWalletsByCoin}
					onSelectAddress={handleSelectAddress}
					isCompact={useCompactTables}
				/>
			)}

			{hasSelectedAddress && (
				<Section innerClassName="mb-27">
					<DelegateTable
						delegates={filteredDelegates}
						isLoading={isLoadingDelegates}
						maxVotes={maxVotes!}
						votes={votes}
						resignedDelegateVotes={resignedDelegateVotes}
						unvoteDelegates={unvoteDelegates}
						voteDelegates={voteDelegates}
						selectedWallet={selectedWallet}
						onContinue={navigateToSendVote}
						isCompact={useCompactTables}
						subtitle={
							resignedDelegateVotes?.length ? (
								<Alert className="mb-6">
									<div data-testid="Votes__resigned-vote">
										<Trans
											i18nKey="VOTE.VOTES_PAGE.RESIGNED_VOTE"
											values={{
												name: currentVotes
													?.find(({ wallet }) => wallet!.isResignedDelegate())
													?.wallet!.username(),
											}}
											components={{ bold: <strong /> }}
										/>
									</div>
								</Alert>
							) : null
						}
					/>
				</Section>
			)}
		</Page>
	);
};
