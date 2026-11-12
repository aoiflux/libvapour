# Specifications

Each file here specifies one area of libvapour: the sources it rests on, the algorithm, the validity rules, the result schema and the acceptance checks. Code is written from the specification, and each source file's record under `docs/provenance/` names the specification it follows and its SHA-256.

## Measurements

Many specifications quote figures measured on the project's own memory captures. Each figure gives the capture, the date and the name of the measurement program that produced it.

The measurement programs and the captures are not published. Captures hold real process memory, and the programs only make sense next to them. A reader cannot re-run a measurement from this repository. The figures record what the project saw when the specification was written. The rules they support are checked by the unit tests and fuzz targets, which run without a capture.
