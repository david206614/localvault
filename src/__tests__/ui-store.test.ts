import { describe, it, expect, beforeEach } from "vitest";
import { useUiStore } from "../stores/ui";

beforeEach(() => {
  // Reset the store between tests
  useUiStore.setState({
    theme: "dark",
    locale: "en",
    toasts: [],
  });
});

describe("ui store", () => {
  it("setTheme updates theme", () => {
    useUiStore.getState().setTheme("light");
    expect(useUiStore.getState().theme).toBe("light");
  });

  it("setLocale updates locale", () => {
    useUiStore.getState().setLocale("es");
    expect(useUiStore.getState().locale).toBe("es");
  });

  it("addToast adds a toast with auto-generated id", () => {
    useUiStore.getState().addToast("Hello", "success");
    const toasts = useUiStore.getState().toasts;
    expect(toasts).toHaveLength(1);
    expect(toasts[0]!.message).toBe("Hello");
    expect(toasts[0]!.type).toBe("success");
  });

  it("addToast defaults to info type", () => {
    useUiStore.getState().addToast("Info message");
    expect(useUiStore.getState().toasts[0]!.type).toBe("info");
  });

  it("removeToast removes by id", () => {
    useUiStore.getState().addToast("msg1");
    useUiStore.getState().addToast("msg2");
    const ids = useUiStore.getState().toasts.map((t) => t.id);
    expect(ids).toHaveLength(2);

    useUiStore.getState().removeToast(ids[0]!);
    const remaining = useUiStore.getState().toasts;
    expect(remaining).toHaveLength(1);
    expect(remaining[0]!.message).toBe("msg2");
  });

  it("addErrorToast adds error toast and returns id", () => {
    const error = { code: "internal", key: "errors.internal", message: "nope" };
    const id = useUiStore.getState().addErrorToast(error);
    const toasts = useUiStore.getState().toasts;
    expect(toasts).toHaveLength(1);
    expect(toasts[0]!.id).toBe(id);
    expect(toasts[0]!.type).toBe("error");
  });
});
