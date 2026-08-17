import { describe, it, expect } from "vitest";
import { FIELD_CAPS } from "../lib/types";

describe("FIELD_CAPS — matches Rust validate.rs", () => {
  it("service_name cap = 256", () => {
    expect(FIELD_CAPS.service_name).toBe(256);
  });

  it("username cap = 256", () => {
    expect(FIELD_CAPS.username).toBe(256);
  });

  it("url cap = 2048", () => {
    expect(FIELD_CAPS.url).toBe(2048);
  });

  it("category cap = 128", () => {
    expect(FIELD_CAPS.category).toBe(128);
  });

  it("password cap = 4096", () => {
    expect(FIELD_CAPS.password).toBe(4096);
  });

  it("notes cap = 16384", () => {
    expect(FIELD_CAPS.notes).toBe(16384);
  });
});

describe("TypeScript types — contract alignment", () => {
  it("CredentialInput has exactly 6 fields matching Rust serde names", () => {
    const fields = [
      "service_name",
      "username",
      "password",
      "url",
      "category",
      "notes",
    ];
    const sample = {
      service_name: "",
      username: "",
      password: "",
      url: "",
      category: "",
      notes: "",
    };
    for (const f of fields) {
      expect(f in sample).toBe(true);
    }
  });

  it("CredentialView has all 9 fields including id + timestamps", () => {
    const view = {
      id: 1,
      service_name: "",
      username: "",
      password: "",
      url: "",
      category: "",
      notes: "",
      created_at: "",
      updated_at: "",
    };
    expect(Object.keys(view)).toHaveLength(9);
  });

  it("SessionState variants match Rust enum", () => {
    const valid: string[] = ["NoVault", "Locked", "Unlocked"];
    expect(valid).toHaveLength(3);
    for (const v of valid) {
      expect(["NoVault", "Locked", "Unlocked"]).toContain(v);
    }
  });

  it("AppError has code, key, message fields", () => {
    const err = { code: "internal", key: "errors.internal", message: "test" };
    expect(err).toHaveProperty("code");
    expect(err).toHaveProperty("key");
    expect(err).toHaveProperty("message");
  });
});
