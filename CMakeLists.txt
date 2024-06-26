cmake_minimum_required(VERSION 3.19)
project(tls-inspector)

include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/../common/include")
include_directories("${PROJECT_SOURCE_DIR}/include")

# add_definitions(-DDEBUG_EXTRA)
# add_definitions(-g)
add_definitions(-Wall)
add_definitions(-Wextra)
add_definitions(-Wno-psabi)
add_definitions(-Wno-error=unused-parameter)

set(SRC
	src/main.cxx
	src/ti.cxx
	src/core.cxx
	src/handlers.cxx
	src/common.cxx
	src/update_task.cxx

	src/net/proxy.cxx

	src/tasks/task_creator.cxx
	src/tasks/task.cxx

	src/crypto/common.cxx
	src/crypto/certificate.cxx
	src/crypto/private_key.cxx
	src/crypto/csr.cxx
	src/crypto/pkcs7.cxx
	src/crypto/cipher.cxx
	src/crypto/digest.cxx
	src/crypto/x509_name.cxx

	src/proxy/proxy.cxx
	)

set(CMAKE_CXX_STANDARD 14)

add_executable(${PROJECT_NAME} ${SRC})

set_target_properties(${PROJECT_NAME}
	PROPERTIES
	COMPILE_FLAGS "${GLOBAL_CFLAGS}"
	LINK_FLAGS "${GLOBAL_LDFLAGS} ${GLOBAL_CFLAGS}"
	)

if (DEFINED CONFIG_ESR_UNIT_TESTS)
target_compile_definitions(${PROJECT_NAME} PRIVATE
	DOCTEST_CONFIG_SUPER_FAST_ASSERTS
	)
else()
target_compile_definitions(${PROJECT_NAME} PRIVATE
	DOCTEST_CONFIG_DISABLE
	)
endif()

target_link_libraries(${PROJECT_NAME}
	pthread
	stdc++fs
	crypto
	ssl
	boost_thread
	)

install (TARGETS ${PROJECT_NAME} DESTINATION bin)
