import { assertEquals, assertNotEquals } from "jsr:@std/assert";
import { parseConsensus } from "../src/directory/consensus.ts";
import { parseMicrodescriptors } from "../src/directory/microdescriptor.ts";
import { PathSelector } from "../src/directory/path_selector.ts";
import { RelayInfo } from "../src/common/types.ts";
import { decodeBase64, randomBytes } from "../src/crypto/utils.ts";

const SAMPLE_CONSENSUS = `
valid-after 2026-08-17 12:00:00
fresh-until 2026-08-17 13:00:00
valid-until 2026-08-17 15:00:00
r GuardRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA= 2026-08-17 10:00:00 1.1.1.1 9001 0
m 3wUeG5O3aZ5h8VbX9N8sC5kE1M7oP3qR4sT5uV6wX8Y=
s Fast Guard Running Stable Valid
r MiddleRelay1 BBBBBBBBBBBBBBBBBBBBBBBBBBB= 2026-08-17 10:00:00 2.2.2.2 9001 0
m jGk8L1vN3pQ5sU7wY9aC2eG4iK6mO8qS0uW2yA4cE6g=
s Fast Running Stable Valid
r ExitRelay1 CCCCCCCCCCCCCCCCCCCCCCCCCCC= 2026-08-17 10:00:00 3.3.3.3 9001 0
m aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
s Exit Fast Running Stable Valid
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
    },
    {
      nickname: "Middle1",
      ip: "20.0.1.1",
      orPort: 9001,
      identityRsa: randomBytes(20),
      ntorOnionKey: randomBytes(32),
      flags: new Set(["Fast", "Running", "Valid"]),
    },
    {
      nickname: "Exit1",
      ip: "30.0.1.1",
      orPort: 9001,
      identityRsa: randomBytes(20),
      ntorOnionKey: randomBytes(32),
      flags: new Set(["Exit", "Fast", "Running", "Valid"]),
    },
  ];

  const [guard, middle, exit] = PathSelector.select3HopPath(dummyRelays);
  assertEquals(guard.nickname, "Guard1");
  assertEquals(middle.nickname, "Middle1");
  assertEquals(exit.nickname, "Exit1");
});
