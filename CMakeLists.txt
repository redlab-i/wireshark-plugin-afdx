# wireshark-plugin-afdx
#
# Copyright 2017 REDLAB-I, LLC <http://redlab-i.ru>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


project(wireshark-plugin-afdx C)
set(PROJECT_VERSION 0.1.0)

set(WERROR 1)

cmake_minimum_required(VERSION 2.6)

find_package(Wireshark)
if(NOT Wireshark_FOUND)
	message(FATAL_ERROR "No wireshark-dev found.")
endif(NOT Wireshark_FOUND)

list(APPEND CMAKE_MODULE_PATH "${Wireshark_CMAKE_MODULES_DIR}")

find_package(GLIB2)
if(NOT GLIB2_FOUND)
	message(FATAL_ERROR "No libglib2.0-dev found.")
endif(NOT GLIB2_FOUND)

include_directories(${GLIB2_INCLUDE_DIRS})
include_directories (${Wireshark_INCLUDE_DIR})

if(NOT CMAKE_INSTALL_LIBDIR)
#	set(CMAKE_INSTALL_LIBDIR ~/.wireshark/plugins)
	set(CMAKE_INSTALL_LIBDIR ${Wireshark_PLUGIN_INSTALL_DIR})
endif(NOT CMAKE_INSTALL_LIBDIR)
message(STATUS "Plug-in will be installed to: ${CMAKE_INSTALL_LIBDIR}")


#To follow FSHS locale files should go to share not lib, but this
#will make packaging too complex
set(PACKAGE_LOCALE_DIR ${CMAKE_INSTALL_LIBDIR}/locale)
set(PACKAGE_LOCALES ru)
get_filename_component(PACKAGE_LOCALE_DIR "${PACKAGE_LOCALE_DIR}" REALPATH)
add_definitions(-DLOCALE_PATH="${PACKAGE_LOCALE_DIR}")
message(STATUS "Locales will be installed to: ${PACKAGE_LOCALE_DIR}")


include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(DISSECTOR_SRC src/packet-afdx.c)
set(DISSECTOR_EXTRA_SRC src/interval_map.c src/afdx_utilities.c)
set(PLUGIN_FILES plugin.c ${DISSECTOR_SRC} ${DISSECTOR_EXTRA_SRC})
set(CLEAN_FILES ${PLUGIN_FILES})

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif(WERROR)


include( UseMakeDissectorReg )
register_dissector_files(plugin.c plugin ${DISSECTOR_SRC} ${DISSECTOR_EXTRA_SRC})


set(LINK_MODE_LIB SHARED)
set(LINK_MODE_MODULE MODULE)
add_library(afdx ${LINK_MODE_MODULE} ${PLUGIN_FILES})
set_target_properties(afdx PROPERTIES PREFIX "")
set_target_properties(afdx PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")
target_link_libraries(afdx ${Wireshark_LIBRARY} ${GLIB2_LIBRARIES} csv)


#generates pot, mo, installs mo to PACKAGE_LOCALE_DIR
#to update po from sources call "pofiles" target
find_package(Gettext)
if (GETTEXT_FOUND)
	set(POT_FILE ${CMAKE_BINARY_DIR}/afdx.pot)
	set(PO_SOURCES ${DISSECTOR_SRC})
	set(LANGS ${PACKAGE_LOCALES})

	find_program(XGETTEXT_CMD xgettext)
	set(_xgettext_option_list --language=C --keyword=_
		--force-po --no-wrap --no-location --omit-header --keyword=N_ -s
		--package-name=${PROJECT_NAME} --package-version=${PROJECT_VERSION})

	ADD_CUSTOM_COMMAND(OUTPUT ${POT_FILE}
		COMMAND ${XGETTEXT_CMD} ${_xgettext_option_list} -o ${POT_FILE} ${PO_SOURCES}
		DEPENDS ${PO_SOURCES}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)

	set(PO_FILES)
	foreach(LANG ${LANGS})
		configure_file(po/${LANG}.po ${LANG}.po COPYONLY)
		list(APPEND PO_FILES "${LANG}.po")
	endforeach()

	ADD_CUSTOM_TARGET(pofiles
		DEPENDS potfiles
		COMMAND cp ${PO_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/po
	)


	GETTEXT_PROCESS_POT_FILE(${POT_FILE} ALL
		INSTALL_DESTINATION ${PACKAGE_LOCALE_DIR}
		LANGUAGES ${LANGS})
else(GETTEXT_FOUND)
	message(FATAL_ERROR "No gettext found.")
endif(GETTEXT_FOUND)

install(TARGETS afdx
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
)
