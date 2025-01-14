import * as useRandomNumberHook from "app/hooks/use-random-number";
import React from "react";
import { render } from "utils/testing-library";

import { PluginCardSkeleton } from "./PluginCardSkeleton";

describe("PluginCardSkeleton", () => {
	beforeAll(() => {
		jest.spyOn(useRandomNumberHook, "useRandomNumber").mockImplementation(() => 1);
	});

	afterAll(() => {
		useRandomNumberHook.useRandomNumber.mockRestore();
	});

	it("should render", async () => {
		const { asFragment, findByTestId } = render(<PluginCardSkeleton />);

		await findByTestId("PluginCardSkeleton");

		expect(asFragment()).toMatchSnapshot();
	});
});
