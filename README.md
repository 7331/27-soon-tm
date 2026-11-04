# 27-soon-tm

iOS 27.0.1 (24A446), iPhone 18 Pro (iPhone19,2).

**1. `CMVideoFormatDescriptionCreateFromHEVCParameterSets` does not validate `parameterSetCount`.**
Verified 3 → 18,432 entries, all accepted, decompression sessions created. iOS 27.2 added kext-side count validation for this field family.

**2. No sign validation on dimensions parsed from HEVC SPS.**
One byte-pair patch produces format descriptions with negative dimensions (e.g. `-82x-120`). 96 such fds in a sweep. Sessions reject them with `0x131`, an undocumented positive OSStatus. Also `-17694` on some CABAC paths, also undocumented.

Both already changed in iOS 27.2.

## Files

- `poc_unbounded_paramsets.swift`
- `poc_negative_dims.swift`

Tested: Xcode 27.2, device build, arm64e.
