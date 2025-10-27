Keywords cuz i couldnt find anything like this on github<br/>
roblox like memory region whitelist,
memory region whitelist,
anticheat memory whitelist

# Memory Whitelist

## How it works

The program operates by utilizing Windows API calls, specifically `NTQueryVirtualMemory`, to analyze the current process's memory:
1. **Whitelisting**:
   - Establish a set of allowed memory addresses
   - Use `WhitelistBase` to initialize this set based on existing memory regions
   - Use `VerifyWhitelist` to go to validation
2. **Memory Querying**:
   - Retrieve information about memory regions, including their state and protection attributes
   - Store relevant information
3. **Validation Loop**:
   - This can be put anywhere as long as it runs often (for example in mc it could be on the tick functions that run 20 times a second or setupandrender)
   - Monitors memory regions to ensure compliance with the whitelist
   - Modify permissions for regions that are not whitelisted back to read/write (causing them to crash the program)
