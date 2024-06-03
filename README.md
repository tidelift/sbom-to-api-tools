This repository contains some examples of using the Tidelift APIs to gather
information about open source library components.

The examples all use a cyclonedx sbom as their entry point and then provide
different outputs depending on the specific example.

Tagged releases are published on GitHub at
https://github.com/tidelift/tidelift-sbom-info/releases and can be downloaded and
run in your environment.

## Current Commands

* `tidelift-sbom-analyzer`: This takes a cyclonedx file as the first argument and
then outputs a CSV file with Tidelift's recommendations about the packages in the
SBOM. Takes an optional argument of `-o output.csv` to write the output to a file.

* `tidelift-sbom-vulnerability-reporter`: This takes a cyclonedx file as the first
argument and then outputs a JSON file with information about any known vulnerabilities
in releases that are listed in the SBOM. Takes an optional argument of
`-o output.json` to write the output to a file.

## Contributing

While this is primarily intended to guide others in the use of the Tidelift API,
contributions to adapt and enhance the existing tools are always welcome. Additional
commands to provide different types of data are also welcome.

## Building from source

If you want to build from source, you can do so by running `make build`. The commands
then all live in the `bin/` subdirectory.

If you need/want to build for an architecture that you're not running on, you can
do any of `make build-windows`, `make linux-x86`, `make linux-arm`, `make mac-arm`,
or `make all-cross` to build binaries for a different OS (or all) which then live
in the named subdirectories of the `bin/` subdirectory.
