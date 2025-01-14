import { useQueryParams } from "app/hooks";
import { FilterOption } from "domains/vote/components/VotesFilter";
import { useMemo } from "react";

import { getParameters } from "../utils/url-parameters";

export const useVoteQueryParameters = () => {
	const queryParameters = useQueryParams();
	const unvoteDelegates = getParameters(queryParameters, "unvote");
	const voteDelegates = getParameters(queryParameters, "vote");
	const filter = (queryParameters.get("filter") || "all") as FilterOption;

	return useMemo(() => ({ filter, unvoteDelegates, voteDelegates }), [filter, unvoteDelegates, voteDelegates]);
};
