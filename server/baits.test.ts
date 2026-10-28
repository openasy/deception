import { describe, expect, it } from "vitest";
import { bait, isTemplate, TEMPLATES } from "./baits.ts";

const input = { token: "k3v9q2m8x1c4b7n5z6a0w2e4", canaryUrl: "https://cdn.example.com/", dnsZone: "canary.example.com" };

describe("baits", () => {
  it("puts the canary's URL in every URL template", () => {
    for (const template of ["link", "kubeconfig", "env", "html"] as const)
      expect(bait({ ...input, template }).content).toContain("https://cdn.example.com/c/k3v9q2m8x1c4b7n5z6a0w2e4");
    expect(bait({ ...input, template: "link" })).toEqual({ file: "", content: "https://cdn.example.com/c/k3v9q2m8x1c4b7n5z6a0w2e4" });
    expect(bait({ ...input, template: "kubeconfig" }).content).toMatch(/server: https:\/\/cdn\.example\.com\/c\/\S+\n/);
    expect(bait({ ...input, template: "html" }).content).toContain('<img src="https://cdn.example.com/c/');
  });

  it("names the canary in the zone for DNS templates", () => {
    expect(bait({ ...input, template: "hostname" }).content).toBe("k3v9q2m8x1c4b7n5z6a0w2e4.canary.example.com");
    expect(bait({ ...input, template: "ssh-config" }).content).toContain("HostName k3v9q2m8x1c4b7n5z6a0w2e4.canary.example.com\n");
  });

  it("writes an AWS credentials file with the key", () => {
    const b = bait({ ...input, template: "aws-credentials", token: "AKIAIOSFODNN7EXAMPLE", secret: "s".repeat(40) });
    expect(b.file).toBe("credentials");
    expect(b.content).toContain("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ssss");
  });

  it("makes new filler each time, so two copies differ", () => {
    expect(bait({ ...input, template: "env" }).content).not.toBe(bait({ ...input, template: "env" }).content);
  });

  it("knows its templates and no others", () => {
    expect(Object.keys(TEMPLATES).every(isTemplate)).toBe(true);
    expect(isTemplate("toString")).toBe(false);
    expect(isTemplate("pdf")).toBe(false);
  });
});
