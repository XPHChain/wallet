import { Contracts } from "@payvo/profiles";
import { PluginController, PluginManager } from "plugins/core";
import { PluginAPI } from "plugins/types";
import { defaultNetMocks, env, waitFor } from "utils/testing-library";

import { HttpPluginService } from "./HttpPluginService";

const config = {
	"desktop-wallet": { permissions: ["HTTP"], urls: ["https://ark-test.payvo.com"] },
	name: "test",
	version: "1.1",
};

describe("HttpPluginService", () => {
	let profile: Contracts.IProfile;
	let manager: PluginManager;
	let ctrl: PluginController;
	let subject: HttpPluginService;

	beforeEach(() => {
		profile = env.profiles().first();
		subject = new HttpPluginService();
		manager = new PluginManager();
		manager.services().register([subject]);
		manager.services().boot();

		defaultNetMocks();
	});

	it("should create an instance", async () => {
		let response: any;

		const fixture = async (api: PluginAPI) => {
			const result = await api.http().create().get("https://ark-test.payvo.com/api/node/fees");
			response = result.json();
		};

		ctrl = new PluginController(config, fixture);
		ctrl.enable(profile);

		manager.plugins().push(ctrl);
		manager.plugins().runAllEnabled(profile);

		await waitFor(() =>
			expect(response).toMatchObject({
				data: expect.anything(),
			}),
		);
	});

	it("should get from url", async () => {
		let response: any;

		const fixture = async (api: PluginAPI) => {
			const result = await api.http().get("https://ark-test.payvo.com/api/node/fees");
			response = result.json();
		};

		ctrl = new PluginController(config, fixture);
		ctrl.enable(profile);

		manager.plugins().push(ctrl);
		manager.plugins().runAllEnabled(profile);

		await waitFor(() =>
			expect(response).toMatchObject({
				data: expect.anything(),
			}),
		);
	});

	it("should fail to get a unknown url", async () => {
		let response: any;
		const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => void 0);

		const fixture = (api: PluginAPI) => {
			api.http()
				.get("https://ark-live.payvo.com")
				.then((result) => result.json())
				.catch((error) => console.log(error));
		};

		ctrl = new PluginController(config, fixture);
		ctrl.enable(profile);

		manager.plugins().push(ctrl);
		manager.plugins().runAllEnabled(profile);

		await waitFor(() => expect(response).toBeUndefined());

		expect(consoleSpy).toHaveBeenCalled();

		jest.clearAllMocks();
	});
});
