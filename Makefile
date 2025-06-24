################################################################################
#                                 CONFIGURATION                                #
################################################################################

NAME = stockholm

SRC_PATH = src/


################################################################################
#                                    SOURCES                                   #
################################################################################


SRC_FILE =	main.rs \
		custom_error/custom_error.rs \
		custom_error/mod.rs \
		sotckholm/sotckholm.rs \
		stockholm/mod.rs \
		stockholm/decryption/decrypt_file.rs \
		sotckholm/decryption/mod.rs \
		sotckholm/encryption/encrypt_file.rs \
		stockholm/encryption/mod.rs \

SRC = $(addprefix ${SRC_PATH}, ${SRC_FILE})


################################################################################
#                                 RULES                                        #
################################################################################

all: ${NAME}

${NAME}:
	cargo build --release

build: all

debug:
	cargo build

clean:
	cargo clean

fclean: clean

re: fclean all