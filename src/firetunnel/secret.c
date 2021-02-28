/*
 * Copyright (C) 2018 Firetunnel Authors
 *
 * This file is part of firetunnel project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "firetunnel.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

static uint8_t key[KEY_LEN];
static uint8_t result[KEY_LEN]; // result of hash function
static uint8_t auth_dictionary[KEY_LEN * KEY_MAX] = {179, 55, 2, 143, 241, 56, 61, 17, 189, 69, 20, 111, 172, 130, 54, 15};
uint8_t enc_dictionary[KEY_LEN * KEY_MAX];

void init_keys(uint16_t port) {
	// open SECRET_FILE and read it
	int fd = open(SECRET_FILE, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Error: cannot open %s\n", SECRET_FILE);
		exit(1);
	}

	struct stat s;
	if (fstat(fd, &s)) {
		fprintf(stderr, "Error: cannot find %s\n", SECRET_FILE);
		exit(1);
	}

	uint8_t *data = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		fprintf(stderr, "Error: cannot read %s\n", SECRET_FILE);
		exit(1);
	}


	// create auth keys
	int i;
	port = htons(port);
	memcpy(auth_dictionary, &port, sizeof(port));
	for (i  = 0; i < KEY_MAX; i++) {
		if (i != 0)
			memcpy(auth_dictionary + i * KEY_LEN, auth_dictionary + (i - 1) * KEY_LEN, KEY_LEN);
		get_hash(data, s.st_size, 0, i);
		memcpy(auth_dictionary + i * KEY_LEN, result, KEY_LEN);
	}

	// create enc keys
	get_hash(auth_dictionary, sizeof(auth_dictionary), 0, i);
	memcpy(enc_dictionary, result, KEY_LEN);
	for (i  = 0; i < KEY_MAX; i++) {
		if (i != 0)
			memcpy(enc_dictionary + i * KEY_LEN, enc_dictionary + (i - 1) * KEY_LEN, KEY_LEN);
		get_hash(data, s.st_size, 0, i);
		memcpy(enc_dictionary + i * KEY_LEN, result, KEY_LEN);
	}

	munmap(data, s.st_size);
	close(fd);
}


// return NULL if fails
uint8_t *get_hash(uint8_t *in, unsigned inlen, uint32_t timestamp, uint32_t seq) {
	// grab the key from the dictionary
	uint32_t index = (seq + timestamp) % KEY_MAX;
	dbg_printf("a:%d ", index);
	fflush(0);
	memcpy(key, auth_dictionary + index * KEY_LEN, KEY_LEN);

	if (blake2(result, KEY_LEN, in, inlen, key, KEY_LEN))
		errExit("blake2");

	return result;
}


