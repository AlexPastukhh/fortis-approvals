## Summary

<!-- What changed and why? -->

## Validation

- [ ] Offline tests passed: `bash scripts/test-source.sh`
- [ ] Source compiles: `python -B -m compileall -q fortis_approvals`
- [ ] No secrets, runtime state, or live credentials added
- [ ] Historical deployment artifacts were not silently repurposed

## Security and runtime impact

- Gateway policy/actor grants changed: **No / Yes — explain**
- Credential or volume changes: **No / Yes — explain**
- Live deployment or container changed: **No**
- New upstream API operation or permission: **No / Yes — explain**

## Owner review

<!-- Identify any change requiring a separate owner decision or release GO. -->
