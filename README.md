# Ed25519

[TOC]

This repo implements a library for elliptic curve signature scheme Edwards-curve Digital Signature Algorithm (EdDSA).
The source code is taken from [this repo](https://github.com/orlp/ed25519)

## Installing the library 

### From source code
```
git clone https://github.com/EddyTheCo/Qed25519.git 

mkdir build
cd build
qt-cmake -G Ninja -DCMAKE_INSTALL_PREFIX=installDir -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_DOCS=OFF -DUSE_THREADS=ON ../Qed25519

cmake --build . 

cmake --install . 
```
where `installDir` is the installation path.
One can choose to build or not the tests and the documentation with the `BUILD_TESTING` and `BUILD_DOCS` variables.

### From GitHub releases
Download the releases from this repo. 

## Adding the libraries to your CMake project 

```CMake
include(FetchContent)
FetchContent_Declare(
	Qted25519	
	GIT_REPOSITORY https://github.com/EddyTheCo/Qed25519.git
	GIT_TAG vMAJOR.MINOR.PATCH 
	FIND_PACKAGE_ARGS MAJOR.MINOR CONFIG  
	)
FetchContent_MakeAvailable(Qted25519)
target_link_libraries(<target> <PRIVATE|PUBLIC|INTERFACE> Qted25519::qed25519)
```

## API reference

You can read the [API reference](https://eddytheco.github.io/Qed25519/) here, or generate it yourself like
```
cmake -DBUILD_DOCS=ON ../
cmake --build . --target doxygen_docs
```

## Contributing

We appreciate any contribution!


You can open an issue or request a feature.
You can open a PR to the `develop` branch and the CI/CD will take care of the rest.
Make sure to acknowledge your work, and ideas when contributing.

