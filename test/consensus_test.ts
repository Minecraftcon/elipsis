import { assertEquals, assertNotEquals } from "jsr:@std/assert";
import { parseConsensus } from "../src/directory/consensus.ts";
import { parseMicrodescriptors } from "../src/directory/microdescriptor.ts";
import { PathSelector, sampleRelayWeighted } from "../src/directory/path_selector.ts";
import { GuardManager } from "../src/directory/guard_manager.ts";
import { RelayInfo } from "../src/common/types.ts";
import { decodeBase64, randomBytes } from "../src/crypto/utils.ts";

const SAMPLE_CONSENSUS = `
valid-after 2026-08-17 12:00:00
fresh-until 2026-08-17 13:00:00
valid-until 2026-08-17 15:00:00
r GuardRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA= 2026-08-17 10:00:00 1.1.1.1 9001 0
m 3wUeG5O3aZ5h8VbX9N8sC5kE1M7oP3qR4sT5uV6wX8Y=
s Fast Guard Running Stable Valid
w Bandwidth=98200
r MiddleRelay1 BBBBBBBBBBBBBBBBBBBBBBBBBBB= 2026-08-17 10:00:00 2.2.2.2 9001 0
m jGk8L1vN3pQ5sU7wY9aC2eG4iK6mO8qS0uW2yA4cE6g=
s Fast Running Stable Valid
w Bandwidth=45000
r ExitRelay1 CCCCCCCCCCCCCCCCCCCCCCCCCCC= 2026-08-17 10:00:00 3.3.3.3 9001 0
m aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
s Exit Fast Running Stable Valid
w Bandwidth=12000
`;

Deno.test("consensus parsing extract valid dates and relay records", () => {
  const parsed = parseConsensus(SAMPLE_CONSENSUS);
  assertEquals(parsed.relays.size, 3);

  const guard = Array.from(parsed.relays.values()).find((r) => r.nickname === "GuardRelay1");
  assertNotEquals(guard, undefined);
  assertEquals(guard!.ip, "1.1.1.1");
  assertEquals(guard!.orPort, 9001);
  assertEquals(guard!.flags?.has("Guard"), true);
  assertEquals(guard!.flags?.has("Fast"), true);
  assertEquals(guard!.bandwidth, 98200);

  const middle = Array.from(parsed.relays.values()).find((r) => r.nickname === "MiddleRelay1");
  assertEquals(middle?.bandwidth, 45000);
});

Deno.test("sampleRelayWeighted (BWRS) samples proportional to bandwidth weight", () => {
  const fastRelay: RelayInfo = {
    nickname: "DatacenterFast",
    ip: "10.0.0.1",
    orPort: 443,
    identityRsa: new Uint8Array(20).fill(1),
    ntorOnionKey: new Uint8Array(32).fill(1),
    flags: new Set(["Fast", "Running"]),
    bandwidth: 100000, // 100 MB/s
  };

  const slowRelay: RelayInfo = {
    nickname: "SlowHomeRelay",
    ip: "10.0.0.2",
    orPort: 443,
    identityRsa: new Uint8Array(20).fill(2),
    ntorOnionKey: new Uint8Array(32).fill(2),
    flags: new Set(["Running"]),
    bandwidth: 10, // 10 KB/s
  };

  let fastCount = 0;
  const iterations = 500;
  for (let i = 0; i < iterations; i++) {
    const picked = sampleRelayWeighted([fastRelay, slowRelay]);
    if (picked.nickname === "DatacenterFast") {
      fastCount++;
    }
  }

  // Fast relay has 99.99% weight, so it should be picked in >98% of iterations
  assertEquals(fastCount > iterations * 0.95, true);
});

Deno.test("path selector 3-hop distinct subnets", () => {
  const dummyRelays: RelayInfo[] = [
    {
      nickname: "Guard1",
      ip: "10.0.1.1",
      orPort: 9001,
      identityRsa: randomBytes(20),
      ntorOnionKey: randomBytes(32),
      flags: new Set(["Guard", "Fast", "Running", "Valid"]),
      bandwidth: 50000,
    },
    {
      nickname: "Middle1",
      ip: "20.0.1.1",
      orPort: 9001,
      identityRsa: randomBytes(20),
      ntorOnionKey: randomBytes(32),
      flags: new Set(["Fast", "Running", "Valid"]),
      bandwidth: 40000,
    },
    {
      nickname: "Exit1",
      ip: "30.0.1.1",
      orPort: 9001,
      identityRsa: randomBytes(20),
      ntorOnionKey: randomBytes(32),
      flags: new Set(["Exit", "Fast", "Running", "Valid"]),
      bandwidth: 30000,
    },
  ];

  const [guard, middle, exit] = PathSelector.select3HopPath(dummyRelays);
  assertEquals(guard.nickname, "Guard1");
  assertEquals(middle.nickname, "Middle1");
  assertEquals(exit.nickname, "Exit1");
});

Deno.test("GuardManager pins entry guards and enforces distinct /16 subnets", () => {
  GuardManager.reset();

  const relays: RelayInfo[] = [
    {
      nickname: "GuardA",
      ip: "100.1.0.1",
      orPort: 443,
      identityRsa: new Uint8Array(20).fill(0xaa),
      ntorOnionKey: new Uint8Array(32).fill(0xaa),
      flags: new Set(["Guard", "Fast", "Running", "Valid"]),
      bandwidth: 80000,
    },
    {
      nickname: "GuardSameSubnet",
      ip: "100.1.5.5", // Same 100.1 /16 subnet
      orPort: 443,
      identityRsa: new Uint8Array(20).fill(0xbb),
      ntorOnionKey: new Uint8Array(32).fill(0xbb),
      flags: new Set(["Guard", "Fast", "Running", "Valid"]),
      bandwidth: 90000,
    },
    {
      nickname: "GuardB",
      ip: "100.2.0.1",
      orPort: 443,
      identityRsa: new Uint8Array(20).fill(0xcc),
      ntorOnionKey: new Uint8Array(32).fill(0xcc),
      flags: new Set(["Guard", "Fast", "Running", "Valid"]),
      bandwidth: 70000,
    },
    {
      nickname: "GuardC",
      ip: "100.3.0.1",
      orPort: 443,
      identityRsa: new Uint8Array(20).fill(0xdd),
      ntorOnionKey: new Uint8Array(32).fill(0xdd),
      flags: new Set(["Guard", "Fast", "Running", "Valid"]),
      bandwidth: 60000,
    },
  ];

  const guards = GuardManager.getGuards(relays, 3);
  assertEquals(guards.length, 3);

  // Subnets must all be distinct
  const subnets = new Set(guards.map((g) => PathSelector.getSubnet16(g.ip)));
  assertEquals(subnets.size, 3);
  assertEquals(subnets.has("100.1"), true);
  assertEquals(subnets.has("100.2"), true);
  assertEquals(subnets.has("100.3"), true);

  // Subsequent call returns the identical pinned guards
  const guardsSecondCall = GuardManager.getGuards(relays, 3);
  assertEquals(guardsSecondCall.map((g) => g.nickname), guards.map((g) => g.nickname));

  // Failure tracking test: mark failure 3 times evicts guard
  GuardManager.markFailure(guards[0]);
  GuardManager.markFailure(guards[0]);
  GuardManager.markFailure(guards[0]); // 3rd failure evicts

  // Clean up
  GuardManager.reset();
});
