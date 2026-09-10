# Versioning and Release

This document describes the versioning and release process of the COSE Library for PHP.
This document is a living document, contents will be updated according to each release.

## Releases

Releases will be versioned using dotted triples, similar to [Semantic Version](http://semver.org/).
For this specific document, we will refer to the respective components of this triple as `<major>.<minor>.<patch>`.
The version number may have additional information, such as "-rc1,-rc2,-rc3" to mark release candidate builds for earlier access.
Such releases will be considered as "pre-releases".

## Minor Release Support Matrix

This matrix is the single source of truth for the branches under support; [SECURITY.md](SECURITY.md) refers to it.

| Version | Supported                              |
|---------|----------------------------------------|
| 4.8.x   | :white_check_mark: (in development)    |
| 4.7.x   | :white_check_mark:                     |
| 4.6.x   | :white_check_mark: (security fix only) |
| 4.5.x   | :white_check_mark: (security fix only) |
| < 4.5.x | :x:                                    |
