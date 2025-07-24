***A pure rust implementation of Secure Real-time Transport Protocol (SRTP)***

This repository holds a workspace with three crates:
- [libsrtp](libsrtp/): the rust implementation of SRTP
- [test\_utils](test_utils/): testing helpers
- [interop\_test](interop_test/): interoperability test with cisco's [libsrtp](https://github.com/cisco/libsrtp)

By default interop tests are not built. Use
```
Cargo test --workspace
```
To build and run the interop tests. Check the interop\_test's crate [build.rs](interop_test/build.rs) for some instructions on building with these tests if it fails to find libsrtp on your system

## License
all three crates are distributed under either of :
- [MIT licence](http://opensource.org/licenses/MIT)
- [Apache license, version 2](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2025 Johan Pascal
