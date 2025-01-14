/* eslint-disable jest/require-top-level-describe */
import { Selector } from "testcafe";

import { buildTranslations } from "../../../app/i18n/helpers";
import { createFixture, mockRequest } from "../../../utils/e2e-utils";
import { goToNews } from "./common";

const itemsPerPage = 15;

const translations = buildTranslations();

createFixture(`News filtering`, [
	mockRequest("https://news.payvo.com/api?coins=ARK&page=1", "news/page-1"),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK%2CETH&page=1&categories=Technical&query=major+league+hacking",
		"news/filtered",
	),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK&page=1&categories=Community%2CEmergency%2CTechnical",
		"news/filtered",
	),
	mockRequest("https://news.payvo.com/api?coins=ARK&page=1&categories=Emergency%2CTechnical", "news/filtered"),
	mockRequest("https://news.payvo.com/api?coins=ARK&page=1&categories=Technical", "news/filtered"),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK&page=1&categories=Technical&query=major+league+hacking",
		"news/filtered",
	),
	mockRequest("https://news.payvo.com/api?coins=ARK%2CETH&page=1&categories=Technical", "news/filtered"),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK&page=1&categories=Technical%2CCommunity%2CEmergency&query=major+league+hacking",
		"news/filtered",
	),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK&page=1&categories=Technical%2CEmergency&query=major+league+hacking",
		"news/filtered",
	),
	mockRequest(
		"https://news.payvo.com/api?coins=ARK&page=1&categories=Technical&query=major+league+hackin",
		"news/filtered",
	),
	mockRequest("https://news.payvo.com/api?coins=ARK&page=1&query=fjdskfjdfsdjfkdsfjdsfsd", "news/empty-response"),
]).beforeEach(async (t) => await goToNews(t));

test("should display news feed", async (t) => {
	await t.expect(Selector('[data-testid="NewsCard"]').exists).ok();
	await t.expect(Selector('[data-testid="NewsCard"]').count).eql(itemsPerPage);
});

test("should filter news results", async (t) => {
	// Filter technical category
	const ark = "NetworkOption__ark.mainnet";
	const query = "major league hacking";

	const queryInput = Selector('[data-testid="NewsOptions__search"]');
	await t.typeText(queryInput, query, { replace: true });

	for (const category of ["Marketing", "Community", "Emergency"]) {
		await t.click(Selector(`[data-testid="NewsOptions__category-${category}"]`));
	}

	await t.expect(Selector('[data-testid="NewsCard"]').exists).ok();
	await t
		.expect(Selector('[data-testid="NewsCard__category"]').withText(translations.NEWS.CATEGORIES.TECHNICAL).exists)
		.ok();
	await t.expect(Selector('[data-testid="NewsCard__content"]').withText(/major league hacking/i).exists).ok();

	// deselect ark network
	await t.click(Selector(`[data-testid="${ark}"]`));

	await t.expect(Selector('[data-testid="EmptyResults"]').exists).ok();
});

test("should show no results screen", async (t) => {
	const query = "fjdskfjdfsdjfkdsfjdsfsd";

	const queryInput = Selector('[data-testid="NewsOptions__search"]');
	await t.typeText(queryInput, query, { replace: true });

	await t.expect(Selector('[data-testid="EmptyResults"]').exists).ok();
});
