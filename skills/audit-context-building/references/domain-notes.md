# Domain-specific context cues

Load only the section relevant to the target. These are prompts for what evidence to collect, not claims that any target is vulnerable.

## Smart contracts

Entries include external/public functions, callbacks, and privileged roles. Record caller identity, storage touched, token/accounting state, and external addresses. For a call into code not in scope, record calldata/value and which outcomes remain unverified, including revert, return values, and re-entry before local writes. Check the actual order of state transitions and calls.

## C/C++ and native code

Entries include parsers, exported functions, IPC handlers, and syscalls. Track pointer ownership, lifetime, lengths, integer widths, out-parameters, and build configuration. An error path can leave an output unset or release a resource earlier than its caller expects. Follow compile-time branches that affect the relevant path.

## Decompiled firmware

Begin at identified task, interrupt, or protocol handlers. Function boundaries and names are uncertain; record the evidence for each. Track persistent memory, NVRAM, DMA, and unresolved ROM/library calls. Keep a coverage note so unexamined handlers are not mistaken for safe ones.

## Web services

Entries include routes, RPC methods, jobs, and queue consumers. Trace middleware registration, authentication and authorization checks, database/cache/session writes, and the identity of the caller. Shared state can couple handlers even without direct calls; check transaction and concurrency assumptions on the requested path.
