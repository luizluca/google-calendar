PROJECT( libopensync-plugin-google-calendar C )

SET( VERSION "0.39" )

SET( OPENSYNC_MIN_VERSION "0.39" )
SET( LIBGCAL_MIN_VERSION "0.9.6" )
SET( Libgcal_FIND_REQUIRED "yes" )

CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

FIND_PACKAGE( OpenSync REQUIRED )
FIND_PACKAGE( GLIB2 REQUIRED )
FIND_PACKAGE( LibXml2 REQUIRED )
FIND_PACKAGE( LibXslt REQUIRED )
FIND_PACKAGE( LibGcal REQUIRED )


INCLUDE( OpenSyncInternal )
INCLUDE( Testing )

ADD_SUBDIRECTORY( src )

OPENSYNC_PACKAGE( ${PROJECT_NAME} ${VERSION} )

