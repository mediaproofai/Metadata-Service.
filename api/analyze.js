import fetch from 'node-fetch';
import exifr from 'exifr';
import { fileTypeFromBuffer } from 'file-type';

export default async function handler(req, res) {
  try {
    // 1. Setup & Validation
    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

    const { mediaUrl } = req.body;
    if (!mediaUrl) return res.status(400).json({ error: 'Missing mediaUrl' });

    console.log(`[MetadataScan] Extracting intel from: ${mediaUrl}`);

    // 2. Fetch File Buffer
    const response = await fetch(mediaUrl);
    if (!response.ok) throw new Error(`Fetch failed: ${response.status}`);
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // 3. Stage 1: Binary Type Verification (Magic Bytes)
    // Hackers often rename .exe to .jpg. This catches that.
    const typeInfo = await fileTypeFromBuffer(buffer);
    const declaredExtension = mediaUrl.split('.').pop().toLowerCase();
    const detectedExtension = typeInfo?.ext || 'unknown';
    
    const isSpoofed = typeInfo && !mediaUrl.toLowerCase().endsWith(typeInfo.ext);

    // 4. Stage 2: Deep Metadata Extraction (EXIF + XMP + IPTC)
    // We scan specifically for "Software", "ModifyDate", and "Device" tags.
    let exifData = {};
    try {
      exifData = await exifr.parse(buffer, {
        tiff: true,
        xmp: true,
        iptc: true,
        icc: true,
        jfif: true,
        gps: true,
        mergeOutput: false // Keep distinct blocks separated for forensic clarity
      });
    } catch (e) {
      console.warn("No standard metadata found (common in social media strips)");
    }

    // 5. Stage 3: Forensic Logic
    const tiff = exifData?.ifd0 || {}; // Image File Directory 0 (Main Image)
    const exif = exifData?.exif || {};  // Standard Exif
    const gps = exifData?.gps || {};    // GPS Block

    // Detect Editing Software
    const software = tiff.Software || tiff.ProcessingSoftware || exifData?.xmp?.CreatorTool || "Unknown";
    const isEdited = software !== "Unknown" && 
      (software.includes("Photoshop") || software.includes("GIMP") || software.includes("Lightroom"));

    // Date Consistency Check
    const originalDate = exif.DateTimeOriginal;
    const digitizeDate = exif.CreateDate;
    const modifyDate = tiff.ModifyDate;
    
    // Logic: If ModifyDate exists and is after OriginalDate, it was altered.
    let timelineStatus = "Consistent";
    if (originalDate && modifyDate && new Date(modifyDate) > new Date(originalDate)) {
      timelineStatus = "Altered after creation";
    }

    // 6. Build the Report
    const report = {
      service: "metadata-forensics-unit",
      status: "complete",
      timestamp: new Date().toISOString(),

      fileIntegrity: {
        declaredType: declaredExtension,
        actualType: detectedExtension,
        mime: typeInfo?.mime || 'unknown',
        isExtensionSpoofed: isSpoofed, // CRITICAL FLAG
        fileSize: buffer.length
      },

      deviceFingerprint: {
        make: tiff.Make || "Unknown (Metadata Stripped)",
        model: tiff.Model || "Unknown",
        lens: exif.LensModel || "Unknown",
        serialNumber: exif.BodySerialNumber || "Unknown", // Unique ID for cameras
        software: software
      },

      provenance: {
        created: originalDate || "Unknown",
        digitized: digitizeDate || "Unknown",
        modified: modifyDate || "Unknown",
        timelineAnalysis: timelineStatus,
        isEdited: isEdited
      },

      locationIntel: {
        hasGPS: !!gps.latitude,
        latitude: gps.latitude || null,
        longitude: gps.longitude || null,
        // Direct link for the analyst
        mapsLink: gps.latitude ? `https://www.google.com/maps?q=${gps.latitude},${gps.longitude}` : null
      },

      // Raw dumps for manual analyst review if needed
      rawTags: {
        xmp: exifData?.xmp ? "Present (XML data available)" : "Missing",
        iptc: exifData?.iptc ? "Present (Press metadata available)" : "Missing"
      }
    };

    return res.status(200).json(report);

  } catch (error) {
    console.error('[Metadata Failure]', error);
    return res.status(500).json({ 
      error: 'Metadata extraction failed', 
      details: error.message 
    });
  }
}
