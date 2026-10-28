import { describe, expect, it } from "vitest";
import { parseTrail } from "./cloudtrail.ts";

const event = {
  eventID: "e1",
  eventTime: "2026-10-28T13:58:12Z",
  eventSource: "sts.amazonaws.com",
  eventName: "GetCallerIdentity",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.201",
  userAgent: "aws-cli/2.17.4",
  userIdentity: { type: "IAMUser", accessKeyId: "AKIAIOSFODNN7EXAMPLE" },
};
const parsed = {
  id: "e1",
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  at: "2026-10-28T13:58:12.000Z",
  source: "198.51.100.201",
  userAgent: "aws-cli/2.17.4",
  detail: "sts:GetCallerIdentity in us-east-1",
};

describe("CloudTrail events", () => {
  it("reads a log file, lookup-events, EventBridge and plain events", () => {
    expect(parseTrail({ Records: [event] })).toEqual([parsed]);
    expect(parseTrail({ Events: [{ EventId: "e1", CloudTrailEvent: JSON.stringify(event) }] })).toEqual([parsed]);
    expect(parseTrail({ "detail-type": "AWS API Call via CloudTrail", detail: event })).toEqual([parsed]);
    expect(parseTrail([{ detail: event }, event])).toEqual([parsed, parsed]);
    expect(parseTrail(event)).toEqual([parsed]);
  });

  it("names a refusal", () => {
    expect(parseTrail({ ...event, eventSource: "s3.amazonaws.com", eventName: "ListBuckets", errorCode: "AccessDenied" })[0]!.detail).toBe(
      "s3:ListBuckets in us-east-1, AccessDenied",
    );
  });

  it("leaves out what is not an event with an access key", () => {
    expect(parseTrail({ Records: [{ ...event, userIdentity: { type: "AWSService" } }, 4, null, "x"] })).toEqual([]);
    expect(parseTrail({ Events: [{ CloudTrailEvent: "{nope" }] })).toEqual([]);
    expect(parseTrail("text")).toEqual([]);
  });
});
