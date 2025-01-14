/* eslint-disable sort-keys-fix/sort-keys-fix */
import { Selector } from "testcafe";

import { buildTranslations } from "../../../app/i18n/helpers";
import { cucumber, getLocation, visitWelcomeScreen } from "../../../utils/e2e-utils";

const translations = buildTranslations();

cucumber("@createProfileRouting", {
	"Given Alice is on the welcome screen": async (t: TestController) => {
		await visitWelcomeScreen(t);
		await t.expect(Selector("span").withText(translations.COMMON.PAYVO_WALLET).exists).ok();
		await t.expect(Selector('[data-testid="Card"]').count).eql(3);
	},
	"When she selects create profile": async (t: TestController) => {
		await t
			.expect(Selector('[data-testid="Card"]').withExactText(translations.PROFILE.CREATE_PROFILE).exists)
			.ok({ timeout: 60_000 });
		await t.click(Selector('[data-testid="Card"]').withExactText(translations.PROFILE.CREATE_PROFILE));
	},
	"Then she is on the create profile page": async (t: TestController) => {
		await t.expect(getLocation()).contains("/profiles/create");
		await t.click(Selector("h1").withExactText(translations.PROFILE.PAGE_CREATE_PROFILE.TITLE));
	},
	"When she selects back": async (t: TestController) => {
		await t.click(Selector("button").withExactText(translations.COMMON.BACK));
	},
	"Then she is back on the welcome page": async (t: TestController) => {
		await t.expect(Selector("span").withText(translations.COMMON.PAYVO_WALLET).exists).ok();
	},
});
