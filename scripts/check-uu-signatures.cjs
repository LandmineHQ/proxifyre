const fs = require("node:fs");
const path = require("node:path");

function fail(message) {
    console.error(`FAIL: ${message}`);
    process.exit(1);
}

function parsePattern(value) {
    const tokens = value.trim().split(/\s+/);
    return {
        values: tokens.map(token => token === "??" ? 0 : Number.parseInt(token, 16)),
        masks: tokens.map(token => token === "??" ? 0 : 0xff),
    };
}

function parseSections(bytes) {
    const peOffset = bytes.readUInt32LE(0x3c);
    if (bytes.readUInt32LE(peOffset) !== 0x00004550) {
        fail("input is not a PE image");
    }

    const sectionCount = bytes.readUInt16LE(peOffset + 0x06);
    const optionalHeaderSize = bytes.readUInt16LE(peOffset + 0x14);
    const sectionTable = peOffset + 0x18 + optionalHeaderSize;
    const sections = [];
    for (let index = 0; index < sectionCount; index++) {
        const offset = sectionTable + index * 0x28;
        const name = bytes
            .toString("ascii", offset, offset + 8)
            .replace(/\0.*$/, "");
        const virtualAddress = bytes.readUInt32LE(offset + 0x0c);
        const rawSize = bytes.readUInt32LE(offset + 0x10);
        const rawOffset = bytes.readUInt32LE(offset + 0x14);
        const characteristics = bytes.readUInt32LE(offset + 0x24);
        sections.push({
            name,
            virtualAddress,
            rawSize,
            rawOffset,
            characteristics,
            data: bytes.subarray(rawOffset, rawOffset + rawSize),
        });
    }

    return sections;
}

function findPattern(sections, pattern) {
    const hits = [];
    for (const section of sections) {
        if ((section.characteristics & 0x20000000) === 0
            && section.name !== ".text") {
            continue;
        }

        const data = section.data;
        for (let offset = 0; offset + pattern.values.length <= data.length; offset++) {
            let matched = true;
            for (let index = 0; index < pattern.values.length; index++) {
                if ((data[offset + index] & pattern.masks[index])
                    !== (pattern.values[index] & pattern.masks[index])) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                hits.push(section.virtualAddress + offset);
            }
        }
    }

    return hits;
}

const profilesPath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.resolve("src/Shared/UuPatchProfiles.json");
const dllPath = process.argv[3];
if (!dllPath) {
    fail("usage: node scripts/check-uu-signatures.cjs [profiles.json] <local_proxy.dll>");
}

const profiles = JSON.parse(fs.readFileSync(profilesPath, "utf8")).profiles;
const bytes = fs.readFileSync(path.resolve(dllPath));
const sections = parseSections(bytes);
let checked = 0;

for (const profile of profiles) {
    console.log(`Profile ${profile.key}`);
    for (const target of profile.targets) {
        if (!target.signature) {
            fail(`${profile.key}/${target.name} has no function signature`);
        }

        checked++;
        const hits = findPattern(sections, parsePattern(target.signature));
        const signatureOffset = Number.parseInt(target.signatureOffset ?? "0", 0);
        const resolved = hits.map(hit => hit + signatureOffset);
        console.log(
            `  ${target.name}: hits=${hits.length}` +
            `${resolved.length > 0 ? ` resolved=${resolved.map(value => `0x${value.toString(16)}`).join(",")}` : ""}`);

        if (hits.length !== 1) {
            fail(`${profile.key}/${target.name} signature must match exactly once`);
        }

        if (target.rva) {
            const expected = Number.parseInt(target.rva, 16);
            if (resolved[0] !== expected) {
                fail(
                    `${profile.key}/${target.name} resolved to ` +
                    `0x${resolved[0].toString(16)}, expected 0x${expected.toString(16)}`);
            }
        }
    }
}

if (checked === 0) {
    fail("no signatures were present in the profile catalog");
}

console.log(`PASS: validated ${checked} unique UU function signatures.`);
