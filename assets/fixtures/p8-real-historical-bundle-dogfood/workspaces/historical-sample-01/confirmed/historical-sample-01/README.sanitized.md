# Sanitized Existing Final Target

This neutral directory represents a final confirmed path that already existed
before a regenerated bundle attempt. P8 contract preflight should reject the
generation attempt with `FINAL_TARGET_EXISTS` instead of allowing a reactive
overwrite.

