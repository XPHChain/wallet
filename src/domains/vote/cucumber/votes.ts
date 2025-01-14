/* eslint-disable sort-keys-fix/sort-keys-fix */
import { Selector } from "testcafe";

import { buildTranslations } from "../../../app/i18n/helpers";
import { cucumber, visitWelcomeScreen } from "../../../utils/e2e-utils";
import { goToProfile } from "../../profile/e2e/common";

const translations = buildTranslations();

cucumber("@voteNavigation", {
	"Given Alice is signed into a profile": async (t: TestController) => {
		await visitWelcomeScreen(t);
		await goToProfile(t);
	},
	"When she select votes from navbar": async (t: TestController) => {
		await t.click(Selector('[data-testid="navbar__useractions"]'));
		await t.expect(Selector('[data-testid="dropdown__option--1"]').withText(translations.COMMON.VOTES).exists).ok();
		await t.click(Selector('[data-testid="dropdown__option--1"]').withText(translations.COMMON.VOTES));
	},
	"Then she is on the votes page": async (t: TestController) => {
		await t.expect(Selector("h1").withText(translations.VOTE.VOTES_PAGE.TITLE).exists).ok();
	},
});
