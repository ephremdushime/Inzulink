const assert = require("node:assert/strict");
const test = require("node:test");
const { availabilityFeedQuery, toPublicAvailabilityProperty } = require("../services/availability-feed");
const {
  createConfirmationToken,
  hashConfirmationToken,
  isValidConfirmationToken
} = require("../services/availability-confirmation");

test("verified feed only selects fresh available listings and excludes sensitive contact fields", () => {
  assert.match(availabilityFeedQuery, /p\.availability_status = 'AVAILABLE'/);
  assert.match(availabilityFeedQuery, /p\.availability_checked_at IS NOT NULL/);
  assert.match(availabilityFeedQuery, /p\.expires_at > NOW\(\)/);
  assert.doesNotMatch(availabilityFeedQuery, /p\.\*/);
  assert.doesNotMatch(availabilityFeedQuery, /contact_phone|latitude|longitude|gate_instructions|\bupi\b/i);
});

test("public availability response only includes approved public fields", () => {
  const response = toPublicAvailabilityProperty({
    property_id: 7,
    title: "Test listing",
    description: "Call 0781234567 or +250 78 123 4567.",
    availability_status: "AVAILABLE",
    availability_checked_at: "2026-11-17T10:00:00Z",
    expires_at: "2026-11-24T10:00:00Z",
    contact_phone: "+250780000000",
    latitude: -1.9,
    longitude: 30.0,
    gate_instructions: "Use rear gate",
    upi: "1/03/01/02/1234",
    avg_rating: "4.5",
    review_count: "2"
  });

  assert.equal(response.property_id, 7);
  assert.equal(response.avg_rating, "4.5");
  assert.equal(response.review_count, 2);
  assert.equal(response.description, "Call [contact hidden] or [contact hidden].");
  assert.equal("contact_phone" in response, false);
  assert.equal("latitude" in response, false);
  assert.equal("longitude" in response, false);
  assert.equal("gate_instructions" in response, false);
  assert.equal("upi" in response, false);
});

test("availability confirmation tokens are random, validated, and stored as one-way hashes", () => {
  const first = createConfirmationToken();
  const second = createConfirmationToken();

  assert.match(first.token, /^[a-f0-9]{64}$/);
  assert.notEqual(first.token, second.token);
  assert.equal(first.tokenHash, hashConfirmationToken(first.token));
  assert.notEqual(first.tokenHash, first.token);
  assert.equal(isValidConfirmationToken(first.token), true);
  assert.equal(isValidConfirmationToken("invalid"), false);
  assert.equal(isValidConfirmationToken(null), false);
});
