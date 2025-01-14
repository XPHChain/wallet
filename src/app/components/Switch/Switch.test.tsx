import { fireEvent, render } from "@testing-library/react";
import React, { useState } from "react";

import { Switch, SwitchOption } from "./Switch";

describe("Switch", () => {
	const onChange = jest.fn();

	const leftOption: SwitchOption = { label: "Option A", value: "a" };
	const rightOption: SwitchOption = { label: "Option B", value: "b" };

	const Wrapper = () => {
		const [value, setValue] = useState("a");

		const change = (value_: string) => {
			onChange(value_);
			setValue(value_);
		};

		return <Switch value={value} onChange={change} leftOption={leftOption} rightOption={rightOption} />;
	};

	beforeEach(() => {
		jest.clearAllMocks();
	});

	it("should render", () => {
		const { asFragment, getByRole, getByText } = render(<Wrapper />);

		expect(getByRole("checkbox")).toBeInTheDocument();
		expect(getByText("Option A")).toBeInTheDocument();
		expect(getByText("Option B")).toBeInTheDocument();
		expect(asFragment()).toMatchSnapshot();
	});

	it("should render small labels", () => {
		const { asFragment } = render(
			<Switch size="sm" value="a" onChange={onChange} leftOption={leftOption} rightOption={rightOption} />,
		);

		expect(asFragment()).toMatchSnapshot();
	});

	it("should render large labels", () => {
		const { asFragment } = render(
			<Switch size="lg" value="a" onChange={onChange} leftOption={leftOption} rightOption={rightOption} />,
		);

		expect(asFragment()).toMatchSnapshot();
	});

	it("should render disabled", () => {
		const { asFragment, getByRole } = render(
			<Switch disabled value="a" onChange={onChange} leftOption={leftOption} rightOption={rightOption} />,
		);

		expect(getByRole("checkbox")).toBeDisabled();
		expect(getByRole("checkbox")).not.toHaveAttribute("checked", "");
		expect(asFragment()).toMatchSnapshot();
	});

	it("should allow changing the selected option by clicking the handle", () => {
		const { getByRole } = render(<Wrapper />);

		fireEvent.click(getByRole("checkbox"));

		expect(onChange).toHaveBeenCalledWith("b");
		expect(getByRole("checkbox")).toBeChecked();

		fireEvent.click(getByRole("checkbox"));

		expect(onChange).toHaveBeenCalledWith("a");
		expect(getByRole("checkbox")).not.toBeChecked();
	});

	it("should allow changing the selected option by clicking the option text", () => {
		const { getByRole, getByText } = render(<Wrapper />);

		fireEvent.click(getByText("Option B"));

		expect(onChange).toHaveBeenCalledWith("b");
		expect(getByRole("checkbox")).toBeChecked();

		fireEvent.click(getByText("Option A"));

		expect(onChange).toHaveBeenCalledWith("a");
		expect(getByRole("checkbox")).not.toBeChecked();
	});

	it("should not select option by clicking the option text when disabled", () => {
		const { getByRole, getByText } = render(
			<Switch disabled value="a" onChange={onChange} leftOption={leftOption} rightOption={rightOption} />,
		);

		expect(getByRole("checkbox")).not.toBeChecked();

		fireEvent.click(getByText("Option B"));

		expect(onChange).not.toHaveBeenCalled();
		expect(getByRole("checkbox")).not.toBeChecked();
	});
});
