# - Try to find LIBGLADE
# Find LIBGLADE headers, libraries and the answer to all questions.
#
#  LIBGLADE_FOUND               True if LIBGLADE got found
#  LIBGLADE_INCLUDE_DIR         Location of LIBGLADE headers 
#  LIBGLADE_LIBRARIES           List of libaries to use LIBGLADE
#  LIBGLADE_DEFINITIONS         Definitions to compile LIBGLADE 
#
#  Copyright (c) 2007 Daniel Gollub <dgollub@suse.de>
#  Copyright (c) 2008 Daniel Friedrich <daniel.friedrich@opensync.org>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

IF ( NOT WIN32 )
	INCLUDE( UsePkgConfig )
	# Take care about libglade-2.0.pc settings
	PKGCONFIG( libglade-2.0 _libglade_include_DIR _libglade_link_DIR _libglade_link_FLAGS _libglade_cflags )
ENDIF ( NOT WIN32 )

#MESSAGE( STATUS "FINDLIBGLADE: ${_libglade_include_DIR}" )
#MESSAGE( STATUS "FINDLIBGLADE: ${_libglade_link_DIR}" )
#MESSAGE( STATUS "FINDLIBGLADE: ${_libglade_link_FLAGS}" )
#MESSAGE( STATUS "FINDLIBGLADE: ${_libglade_cflags}" )

# Look for LIBGLADE include dir and libraries, and take care about pkg-config first...
FIND_PATH( LIBGLADE_INCLUDE_DIR glade/glade.h PATH_SUFFIXES libglade-2.0 PATHS ${_libglade_include_DIR} NO_DEFAULT_PATH )
#MESSAGE( STATUS "FINDLIBGLADEDIR: ${LIBGLADE_INCLUDE_DIR}" )
FIND_PATH( LIBGLADE_INCLUDE_DIR glade/glade.h PATH_SUFFIXES libglade-2.0)
#MESSAGE( STATUS "FINDLIBGLADEDIR: ${LIBGLADE_INCLUDE_DIR}" )

FIND_LIBRARY( LIBGLADE_LIBRARIES glade-2.0 PATHS ${_libglade_link_DIR} NO_DEFAULT_PATH )
#MESSAGE( STATUS "FINDLIBGLADE: ${LIBGLADE_LIBRARIES}" )
FIND_LIBRARY( LIBGLADE_LIBRARIES glade-2.0 )
#MESSAGE( STATUS "FINDLIBGLADE: ${LIBGLADE_LIBRARIES}" )

# Report results
IF ( LIBGLADE_LIBRARIES AND LIBGLADE_INCLUDE_DIR )	
	SET( LIBGLADE_FOUND 1 )
	IF ( NOT LIBGLADE_FIND_QUIETLY )
		MESSAGE( STATUS "Found LIBGLADE: ${LIBGLADE_LIBRARIES}" )
	ENDIF ( NOT LIBGLADE_FIND_QUIETLY )
ELSE ( LIBGLADE_LIBRARIES AND LIBGLADE_INCLUDE_DIR )	
	IF ( LIBGLADE_FIND_REQUIRED )
		MESSAGE( SEND_ERROR "Could NOT find LIBGLADE" )
	ELSE ( LIBGLADE_FIND_REQUIRED )
		IF ( NOT LIBGLADE_FIND_QUIETLY )
			MESSAGE( STATUS "Could NOT find LIBGLADE" )	
		ENDIF ( NOT LIBGLADE_FIND_QUIETLY )
	ENDIF ( LIBGLADE_FIND_REQUIRED )
ENDIF ( LIBGLADE_LIBRARIES AND LIBGLADE_INCLUDE_DIR )	

# Hide advanced variables from CMake GUIs
MARK_AS_ADVANCED( LIBGLADE_LIBRARIES LIBGLADE_INCLUDE_DIR )
