#[=======================================================================[

FindAsio
---------

Find asio includes and library.

Imported Targets
^^^^^^^^^^^^^^^^

An :ref:`imported target <Imported targets>` named
``ASIO::ASIO`` is provided if asio has been found.

Result Variables
^^^^^^^^^^^^^^^^

This module defines the following variables:

``ASIO_FOUND``
  True if asio was found, false otherwise.
``ASIO_INCLUDE_DIRS``
  Include directories needed to include asio headers.
``ASIO_LIBRARIES``
  Libraries needed to link to asio.
``ASIO_VERSION``
  The version of asio found.
``ASIO_VERSION_MAJOR``
  The major version of asio.
``ASIO_VERSION_MINOR``
  The minor version of asio.
``ASIO_VERSION_PATCH``
  The patch version of asio.

Cache Variables
^^^^^^^^^^^^^^^

This module uses the following cache variables:

``ASIO_LIBRARY``
  The location of the asio library file.
``ASIO_INCLUDE_DIR``
  The location of the asio include directory containing ``asio.h``.

The cache variables should not be used by project code.
They may be set by end users to point at asio components.
#]=======================================================================]

find_library(asio_LIBRARY
  NAMES
  	asio
	libasio
  )
mark_as_advanced(asio_LIBRARY)

find_path(asio_INCLUDE_DIR
  NAMES asio.h
  )
mark_as_advanced(asio_INCLUDE_DIR)

#-----------------------------------------------------------------------------
# Extract version number if possible.
set(_ASIO_H_REGEX "#[ \t]*define[ \t]+ASIO_VERSION_(MAJOR|MINOR|PATCH)[ \t]+[0-9]+")
if(ASIO_INCLUDE_DIR AND EXISTS "${ASIO_INCLUDE_DIR}/asio.h")
  file(STRINGS "${ASIO_INCLUDE_DIR}/asio.h" _ASIO_H REGEX "${_ASIO_H_REGEX}")
else()
  set(_ASIO_H "")
endif()
foreach(c MAJOR MINOR PATCH)
  if(_ASIO_H MATCHES "#[ \t]*define[ \t]+ASIO_VERSION_${c}[ \t]+([0-9]+)")
    set(_ASIO_VERSION_${c} "${CMAKE_MATCH_1}")
  else()
    unset(_ASIO_VERSION_${c})
  endif()
endforeach()

if(DEFINED _ASIO_VERSION_MAJOR AND DEFINED _ASIO_VERSION_MINOR)
  set(ASIO_VERSION_MAJOR "${_ASIO_VERSION_MAJOR}")
  set(ASIO_VERSION_MINOR "${_ASIO_VERSION_MINOR}")
  set(ASIO_VERSION "${ASIO_VERSION_MAJOR}.${ASIO_VERSION_MINOR}")
  if(DEFINED _ASIO_VERSION_PATCH)
    set(ASIO_VERSION_PATCH "${_ASIO_VERSION_PATCH}")
    set(ASIO_VERSION "${ASIO_VERSION}.${ASIO_VERSION_PATCH}")
  else()
    unset(ASIO_VERSION_PATCH)
  endif()
else()
  set(ASIO_VERSION_MAJOR "")
  set(ASIO_VERSION_MINOR "")
  set(ASIO_VERSION_PATCH "")
  set(ASIO_VERSION "")
endif()
unset(_ASIO_VERSION_MAJOR)
unset(_ASIO_VERSION_MINOR)
unset(_ASIO_VERSION_PATCH)
unset(_ASIO_H_REGEX)
unset(_ASIO_H)

#-----------------------------------------------------------------------------
# Set Find Package Arguments
include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(asio
    FOUND_VAR asio_FOUND
    REQUIRED_VARS ASIO_LIBRARY ASIO_INCLUDE_DIR
    VERSION_VAR ASIO_VERSION
    HANDLE_COMPONENTS
        FAIL_MESSAGE
        "Could NOT find ASIO"
)

set(ASIO_FOUND ${asio_FOUND})

#-----------------------------------------------------------------------------
# Provide documented result variables and targets.
if(ASIO_FOUND)
  set(ASIO_INCLUDE_DIRS ${ASIO_INCLUDE_DIR})
  set(ASIO_LIBRARIES ${ASIO_LIBRARY})
  if(NOT TARGET ASIO::ASYNC)
    add_library(ASIO::ASYNC UNKNOWN IMPORTED)
    set_target_properties(ASIO::ASYNC PROPERTIES
      IMPORTED_LOCATION "${ASIO_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${ASIO_INCLUDE_DIRS}"
      )
  endif()
endif()
