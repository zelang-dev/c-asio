#[=======================================================================[

Copyright (c) 2019 John Norrbin <jlnorrbin@johnex.se>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

FindopenTLS
------------

Find the openTLS encryption library.

Optional Components
^^^^^^^^^^^^^^^^^^^

This module supports two optional components: SSL and TLS.  Both
components have associated imported targets, as described below.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following imported targets:

openTLS::TLS
    The openTLS tls library, if found. Requires and includes OpenSSL::SSL and OpenSSL::Crypto automatically.

Result Variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``OPENTLS_FOUND``
    System has the openTLS library. If no components are requested it only requires the crypto library.
``OPENTLS_INCLUDE_DIR``
    The openTLS include directory.
``OPENTLS_LIBRARY``
    The openTLS TLS library.
``OPENTLS_LIBRARIES``
    All openTLS libraries.
``OPENTLS_VERSION``
    This is set to $major.$minor.$revision (e.g. 2.6.8).

Hints
^^^^^

Set OPENTLS_ROOT_DIR to the root directory of an openTLS installation.

]=======================================================================]

# Find TLS Library
find_library(opentls_LIBRARY
    NAMES
        opentls
        libopentls
        tls
        libtls
        retls
        libretls
)
mark_as_advanced(opentls_LIBRARY)

# Find Include Path
find_path(opentls_INCLUDE_DIR
    NAMES tls.h
)
mark_as_advanced(opentls_INCLUDE_DIR)

include (FindPackageHandleStandardArgs)
# Set Find Package Arguments
find_package_handle_standard_args(opentls
    FOUND_VAR opentls_FOUND
    REQUIRED_VARS OPENTLS_LIBRARY OPENTLS_INCLUDE_DIR
    VERSION_VAR OPENTLS_VERSION
    HANDLE_COMPONENTS
        FAIL_MESSAGE
        "Could NOT find openTLS, try setting the path to openTLS using the OPENTLS_ROOT_DIR environment variable"
)

set(OPENTLS_FOUND ${opentls_FOUND})
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
set(OPENTLS_LIBRARY ${OPENTLS_LIBRARY} ${OPENSSL_LIBRARIES})
set(OPENTLS_INCLUDE_DIR ${opentls_LIBRARY})

# openTLS Found
if(OPENTLS_FOUND)
	set(OPENTLS_INCLUDE_DIRS ${OPENTLS_INCLUDE_DIR})
	set(OPENTLS_LIBRARIES ${OPENTLS_LIBRARY})
    # Set OPENTLS::TLS
    if(NOT TARGET OPENTLS::TLS)
        add_library(OPENTLS::TLS UNKNOWN IMPORTED)
        set_target_properties(OPENTLS::TLS PROPERTIES
			IMPORTED_LOCATION "${OPENTLS_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${OPENTLS_INCLUDE_DIRS}"
        )
    endif() # OPENTLS::TLS
endif(OPENTLS_FOUND)
