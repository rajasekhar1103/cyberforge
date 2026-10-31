# Timestamp Analysis

Records: 1000
eventtime is 19 digits = Unix nanoseconds. All eventtime values convert (as if UTC epoch) to the same wall-clock as date/time (08:48:26 ...), despite tz=+0530. Therefore eventtime in this sample appears to be a local-wall-clock epoch (not true UTC), OR date/time is UTC with tz label only. Discrepancy: naive UTC conversion of eventtime equals local wall time, so treating eventtime as UTC then converting to +0530 would shift by 5h30m. Preserve original values; canonicalization deferred.

No missing/invalid timestamps observed. eventtime monotonically increasing (ordered).
