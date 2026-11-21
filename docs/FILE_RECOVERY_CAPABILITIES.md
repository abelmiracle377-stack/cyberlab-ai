# CyberLab AI — File Recovery and Digital Forensics: capabilities and limits

## Two different recovery modes

The File & Picture Recovery workspace contains both a small browser-local signature carver and a more capable paired-Linux forensic-image workflow. They should not be confused:

- **Browser-local signature carving** scans a user-selected file/image in the current browser tab. It is capped at 256 MB and recognises contiguous JPEG, PNG, GIF and PDF signatures only. It computes SHA-256, returns candidate byte ranges and allows preview/download. It does not parse a filesystem, recover arbitrary document formats, restore filenames or guarantee that the candidate is valid.
- **Forensic disk-image recovery** runs through the paired Kali/CyberLab companion on the user's local Linux machine. It requires the relevant system tools and appropriate disk permissions. The hosted Vercel process cannot directly inspect the user's physical disks.

## Forensic image acquisition

- Lists block devices using lsblk for inventory; it does not mount the source.
- Requires the operator to select a source device and retype its exact device path.
- Rejects mounted source partitions and validates that the image destination is on a different physical device.
- Creates a new image file and ddrescue map file without overwriting existing output.
- Uses GNU ddrescue's first non-scraping pass (ddrescue -f -n); it does not intentionally write to the source device.
- Acquisition runs as a background job. Preserve both the image and map file; the map records rescued and unreadable regions and is important for safe resume/follow-up work.

A live system can still be writing to the source disk even if the acquisition command itself reads it. Best practice is to power down and boot from trusted live media, avoid mounting the affected disk, and image it to a separate drive. Running the companion as root grants it significant local privileges; stop it when the task is complete.

## Image inspection and filesystem-aware undelete

- blkid probes filesystem signatures without mounting or modifying the image.
- Sleuth Kit mmls enumerates allocated partition boundaries.
- Sleuth Kit fsstat inspects metadata for a partition start revalidated against mmls.
- Sleuth Kit fls recursively lists deleted filesystem entries, retaining original names/paths and inodes.
- Sleuth Kit icat recovers one selected inode to a destination on a different physical drive.
- A bounded bulk undelete workflow can recover up to the requested maximum (the UI currently requests at most 200 files) and records per-file hashes/manifests.

Filesystem-aware undelete works best when filesystem metadata and the relevant data blocks remain intact. It may fail when metadata has been overwritten, the file was fragmented, the filesystem is unsupported, encryption prevents interpretation, or the storage device has trimmed/garbage-collected the deleted blocks.

## Signature carving

- Foremost supports a configurable allow-listed set of common photo, video, audio, document and archive signatures and writes to a new folder on a different drive.
- PhotoRec supports a much wider range (480+ file formats according to the project documentation) and is useful when filesystem metadata is damaged or absent.
- Both are background jobs against a completed, verified CyberLab acquisition image. PhotoRec output is placed in a new directory on a separate drive and receives a SHA-256 manifest.
- Carving generally does not preserve original filenames, directory structure, timestamps or filesystem metadata. It can produce partial, duplicate, corrupt or false-positive candidates. A recovered file must be opened/validated and, where relevant, checked against independent evidence.

## Artifact inspection

The same workspace can inspect selected recovered artifacts without executing them:

- Apple plist parser: bounded structural summary for binary or XML property lists.
- SQLite parser: read-only immutable database table/column/count inspection and bounded row samples.
- Windows registry hive inspection uses the local reglookup/hivexget tools where installed.

These are parsers and metadata views, not a full forensic suite. They do not execute recovered content, automatically decrypt evidence, reconstruct every application database, or provide comprehensive timeline analysis.

## Operational and recovery limitations

- The browser-local carver is limited to 256 MB and four contiguous signature families (JPEG, PNG, GIF, PDF). It is not a general-purpose data recovery engine.
- Disk-image acquisition and recovery require a paired local Linux/Kali machine, installed tools (gddrescue, testdisk/PhotoRec, Foremost, Sleuth Kit) and appropriate permissions. Vercel cannot see local physical disks.
- Recovery output must go to a separate physical drive; never recover to the original source disk.
- A completed acquisition does not mean all source sectors were readable. Check ddrescue's map/log and job return code.
- SSD TRIM, encryption, overwritten blocks, physical damage, fragmentation and filesystem corruption can make recovery impossible or incomplete.
- SHA-256 manifests prove the identity of the recovered output at the time it was hashed; they do not prove authenticity, completeness or that the content is uncorrupted.
- Companion acquisition/recovery jobs are held in local process memory. Restarting the companion can lose the dashboard's in-memory job tracking even though the image/output files remain on disk.
- Never mount, repair or write to the original evidence source during acquisition. Preserve originals and document chain of custody for evidentiary use.

## Safety and evidence handling

Use the workflow only on devices and files you own or are explicitly authorised to examine. Preserve the original media, record who acquired it and when, retain the ddrescue map and manifests, use a separate destination drive, and keep recovered data private. A hash is a provenance aid, not proof that an image or file is admissible or forensically complete.
