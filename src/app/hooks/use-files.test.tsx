import { act, renderHook } from "@testing-library/react-hooks";
import electron from "electron";
import os from "os";

import { useFiles } from "./use-files";

describe("useFiles", () => {
	it("should read file contents", () => {
		const { result } = renderHook(() => useFiles());

		const { content, name, extension } = result.current.readFileContents("filePath");

		expect(extension).toBe("");
		expect(name).toBe("filePath");

		expect(content).toBeInstanceOf(Buffer);
		expect(content.toString()).toBe("test mnemonic");
	});

	it("should open file", () => {
		// @ts-ignore
		const showOpenDialogMock = jest.spyOn(electron.remote.dialog, "showOpenDialog").mockImplementation(() => ({
			filePaths: ["filePath"],
		}));

		const { result } = renderHook(() => useFiles());

		act(() => {
			result.current.openFile({ extensions: ["json"] });
		});

		expect(showOpenDialogMock).toHaveBeenCalledWith({
			defaultPath: os.homedir(),
			filters: [{ extensions: ["json"], name: "" }],
			properties: ["openFile"],
		});

		// @ts-ignore
		const showOpenDialogEmptyFilesMock = jest
			.spyOn(electron.remote.dialog, "showOpenDialog")
			.mockImplementation(() => ({ filePaths: [] } as any));

		act(() => {
			result.current.openFile({ extensions: ["json"] });
		});

		expect(showOpenDialogMock).toHaveBeenCalledWith({
			defaultPath: os.homedir(),
			filters: [{ extensions: ["json"], name: "" }],
			properties: ["openFile"],
		});

		showOpenDialogMock.mockRestore();
		showOpenDialogEmptyFilesMock.mockRestore();
	});
});
