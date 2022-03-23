# dpu_crypto
Cryptographic primitives for DPUs

One needs an UPMEM SDK installed in order to compile and use this project.

## Documentation

The documentation can be generated using the following command:
```
$ cd dpu_crypto
$ make apidoc
```

## Configuration

All features can be enabled/disabled using the include/config.h file.

## Compiling

To compile the tests and the library, you can simply run `make` from the root directory:
```
$ cd dpu_crypto
$ make
```

All tests are located in the tests subdirectory.

## Tests

After compiling the tests, one can start them by executing the corresponding host program.
