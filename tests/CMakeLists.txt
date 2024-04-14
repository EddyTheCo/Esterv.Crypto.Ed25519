foreach(app  rfc8032 tip14)
	add_executable(${app} ${app}.cpp)
	target_link_libraries(${app} PRIVATE qed25519)
	add_test(NAME ${app} COMMAND ${app})
endforeach()

