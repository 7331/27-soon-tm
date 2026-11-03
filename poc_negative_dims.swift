// poc_negative_dims.swift
// PoC: CMVideoFormatDescriptionCreateFromHEVCParameterSets performs no sign validation
// on dimensions parsed from crafted SPS bytes. On iOS 27.0.1 (24A446) it happily builds
// format descriptions with negative width/height.
//
// What it does:
//   1. takes a valid SPS NAL (any 640x480 encoder output works)
//   2. patches one byte pair (offset 23, big-endian) to specific values
//   3. builds fds and sessions, records what comes back
//
// Observed on iPhone19,2 / iOS 27.0.1 / 24A446:
//
//   byte-pair value  fd        session
//   ---------------  --------  --------------------------------------
//   1                ok        ok
//   256              ok        kVTVideoDecoderMalfunctionErr (-12911)
//   1023             ok        kVTVideoDecoderMalfunctionErr (-12911)
//   1024             ok        ok
//   8191             ok        305 (0x131)  <- undocumented POSITIVE OSStatus
//
//   (2-byte sweep across SPS offsets 19-26 produced 96 fds with negative
//    dimensions such as -82x-120, -164x-120. VTDecompressionSessionCreate
//    rejected all of them with 0x131. Zero sessions accepted.)
//
// Two things worth noting:
//   - CoreMedia does not validate the sign of parsed dimensions
//   - 0x131 is not in any VideoToolbox/CoreMedia public header
//
// The session layer rejects before the kext sees the fd, so this is a userland
// validation gap, not a kernel bug. It is the kind of missing check that 27.2's
// kext-side "count is out of range" additions are the alternative approach to.

import CoreMedia
import VideoToolbox
import Foundation

func pocNegativeDims(sps: Data, vps: Data, pps: Data) {
    let cliffValues: [UInt16] = [1, 256, 1023, 1024, 8191]

    for value in cliffValues {
        var patchedSPS = sps
        guard patchedSPS.count > 24 else { continue }
        patchedSPS[23] = UInt8(value >> 8)
        patchedSPS[24] = UInt8(value & 0xFF)

        let payloads = [vps, patchedSPS, pps]
        var pointers = [UnsafePointer<UInt8>]()
        var buffers = [UnsafeMutablePointer<UInt8>]()
        var sizes = [Int]()
        for data in payloads {
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
            data.copyBytes(to: buffer, count: data.count)
            buffers.append(buffer)
            pointers.append(UnsafePointer(buffer))
            sizes.append(data.count)
        }
        defer { for b in buffers { b.deallocate() } }

        var fd: CMFormatDescription?
        let fdStatus = CMVideoFormatDescriptionCreateFromHEVCParameterSets(
            allocator: kCFAllocatorDefault,
            parameterSetCount: payloads.count,
            parameterSetPointers: &pointers,
            parameterSetSizes: &sizes,
            nalUnitHeaderLength: 4,
            extensions: nil,
            formatDescriptionOut: &fd)
        guard fdStatus == noErr, let fd else {
            print("value=\(value) fd rejected: \(fdStatus)")
            continue
        }
        let dims = CMVideoFormatDescriptionGetDimensions(fd)
        print("value=\(value) dims=\(dims.width)x\(dims.height)")

        var session: VTDecompressionSession?
        let sessionStatus = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault, formatDescription: fd,
            decoderSpecification: nil, imageBufferAttributes: nil,
            outputCallback: nil, decompressionSessionOut: &session)
        print("value=\(value) session: \(sessionStatus)")
        if let session { VTDecompressionSessionInvalidate(session) }
    }
}
