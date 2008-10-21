# Copyright (c) 2007 Daniel Gollub <dgollub@suse.de>

IF ( WIN32 )
	SET( SYMBOLS_VISIBILITY "" )
ENDIF ( WIN32 )

IF ( CMAKE_COMPILER_IS_GNUCC ) 
	SET( SYMBOLS_VISIBILITY "-fvisibility=hidden" )
ENDIF ( CMAKE_COMPILER_IS_GNUCC ) 

IF (CMAKE_SYSTEM MATCHES "SunOS-5*.")	
	SET( SYMBOLS_VISIBILITY "-xldscope=hidden" )
ENDIF (CMAKE_SYSTEM MATCHES "SunOS-5*.")	